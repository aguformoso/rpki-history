import ipaddress
import os
from datetime import UTC, datetime, timedelta

import falcon
import psycopg
import psycopg.sql as sql
from psycopg.types.range import Range
from swagger_ui import falcon_api_doc

db_host = os.environ['POSTGRES_HOST']
db_dbname = os.environ['POSTGRES_DB']
db_user = os.environ['POSTGRES_RO_USER']
with open('/run/secrets/postgres-ro-pw', 'r') as f:
    db_password = f.read()
custom_location = os.environ.get('CUSTOM_LOCATION', default='').rstrip('/')

# These are the column names which should be retrieved from the database.
vrp_dict_fields = ['prefix', 'asn', 'max_length', 'visible']


def rows_to_vrp(c: psycopg.Cursor) -> list:
    """Convert the rows from the current result set of the cursor to a list of VRPs.

    Each VRP is in a dictionary containing fields specified by vrp_dict_fields.
    """
    if c.description is None:
        return list()
    # To be robust against changes in the database schema and/or reordering of columns,
    # use a index map.
    cn_idx = {column.name: idx for idx, column in enumerate(c.description)}
    ret = [{k: row[cn_idx[k]] for k in vrp_dict_fields} for row in c.fetchall()]
    return ret


def get_covering_vrps_for_prefix_at_time(c: psycopg.Cursor, prefix, timestamp: datetime) -> list:
    c.execute(
        """
        SELECT * FROM vrps
        WHERE prefix >>= %s
        AND visible @> %s
    """,
        (prefix, timestamp),
    )
    return rows_to_vrp(c)


def get_covering_vrps_for_prefix_within_timerange(
    c: psycopg.Cursor, prefix, timerange: Range
) -> list:
    """Return all covering VRPs for the specified prefix whose visible range overlaps
    with the specified timerange.
    """
    c.execute(
        """
        SELECT * FROM vrps
        WHERE prefix >>= %s
        AND visible && %s
        ORDER BY visible
    """,
        (prefix, timerange),
    )
    return rows_to_vrp(c)


def get_rpki_status(c: psycopg.Cursor, prefix, timestamp: datetime, asn: int) -> dict:
    """Infer the RPKI status for the specified prefix/origin ASN combination at the
    specified timestamp.

    Return the result as a dictionary, ready for serialization.

    See: https://www.rfc-editor.org/rfc/rfc6811#section-2.1
    """
    vrps = get_covering_vrps_for_prefix_at_time(c, prefix, timestamp)
    if not vrps:
        return {'status': 'NotFound'}
    same_origin_asn_found = False
    for vrp in vrps:
        if vrp['asn'] == 0 or vrp['asn'] != asn:
            continue
        same_origin_asn_found = True
        if prefix.prefixlen <= vrp['max_length']:
            return {'status': 'Valid'}
    if same_origin_asn_found:
        return {
            'status': 'Invalid',
            'reason': {
                'code': 'moreSpecific',
                'description': 'Covering VRP with matching origin ASN found, but queried prefix is more specific '
                'than maxLength attribute allows.',
            },
        }
    return {
        'status': 'Invalid',
        'reason': {
            'code': 'noMatchingOrigin',
            'description': 'No covering VRP with matching origin ASN found.',
        },
    }


def get_available_dump_time_range(
    c: psycopg.Cursor,
) -> tuple[datetime, datetime] | tuple[None, None]:
    """Get the latest dump time as datetime from the database."""
    c.execute('SELECT earliest, latest FROM dump_time_range')
    res = c.fetchone()
    if res is None:
        return None, None
    earliest, latest = res
    return earliest, latest


def parse_timestamp(timestamp: str, param_name: str) -> datetime:
    """Parse a timestamp either in %Y-%m-%dT%H:%M:%S or unix epoch format and return the
    corresponding datetime.
    """
    try:
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=UTC)
    except ValueError:
        pass
    try:
        return datetime.fromtimestamp(int(timestamp), tz=UTC)
    except ValueError:
        raise falcon.HTTPInvalidParam(
            'Timestamp has to be in epoch or %Y-%m-%dT%H:%M:%S format.', param_name
        )


class VRPResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host, dbname=db_dbname, user=db_user, password=db_password, autocommit=True
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return all covering VRPs for the requested prefix at the specified timestamp.

        If no timestamp is specified, return data for the latest available dump in the
        database.
        """
        if not req.has_param('prefix'):
            raise falcon.HTTPMissingParam('prefix')

        try:
            parsed_prefix = ipaddress.ip_network(req.get_param('prefix', required=True).strip())
        except ValueError as e:
            raise falcon.HTTPInvalidParam(str(e), 'prefix')

        if req.has_param('timestamp') and (
            req.has_param('timestamp__gte') or req.has_param('timestamp__lte')
        ):
            raise falcon.HTTPBadRequest(
                description='timestamp and timestamp__gte/lte parameters are exclusive.'
            )

        with self.conn.cursor() as c:
            earliest, latest = get_available_dump_time_range(c)
            if req.has_param('timestamp'):
                timestamp = parse_timestamp(req.get_param('timestamp', required=True), 'timestamp')
                if earliest is None or timestamp < earliest or timestamp > latest:
                    raise falcon.HTTPNotFound(
                        description='Requested timestamp is outside of available data.'
                    )
                vrps = get_covering_vrps_for_prefix_at_time(c, parsed_prefix, timestamp)
            elif req.has_param('timestamp__gte') or req.has_param('timestamp__lte'):
                timestamp_start = None
                if req.has_param('timestamp__gte'):
                    timestamp_start = parse_timestamp(
                        req.get_param('timestamp__gte', required=True), 'timestamp__gte'
                    )
                timestamp_end = None
                if req.has_param('timestamp__lte'):
                    timestamp_end = parse_timestamp(
                        req.get_param('timestamp__lte', required=True), 'timestamp__lte'
                    )

                if (
                    earliest is None
                    or (timestamp_start and timestamp_start < earliest)
                    or (timestamp_end and timestamp_end > latest)
                ):
                    raise falcon.HTTPNotFound(
                        description='Requested timerange is outside of available data.'
                    )
                if timestamp_start and timestamp_end and timestamp_end < timestamp_start:
                    raise falcon.HTTPBadRequest(
                        description='Requested end time is before start time.'
                    )

                timerange = Range(timestamp_start, timestamp_end, bounds='[]')
                vrps = get_covering_vrps_for_prefix_within_timerange(c, parsed_prefix, timerange)
            else:
                timestamp = latest
                if timestamp is None:
                    raise falcon.HTTPInternalServerError(
                        description='Failed to get latest dump time.'
                    )
                vrps = get_covering_vrps_for_prefix_at_time(c, parsed_prefix, timestamp)
            # Format for JSON serialization.
            for vrp in vrps:
                vrp['prefix'] = vrp['prefix'].compressed
                visible_range = vrp['visible']
                # If the VRP is visible in the latest dump, the range has no upper
                # bound.
                if visible_range.upper is None:
                    visible_to = latest.isoformat()
                else:
                    visible_to = visible_range.upper.isoformat()
                vrp['visible'] = {'from': vrp['visible'].lower.isoformat(), 'to': visible_to}
            resp.media = vrps


class StatusResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host, dbname=db_dbname, user=db_user, password=db_password, autocommit=True
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return the RPKI status for the specified prefix and originating ASN."""
        required_params = ['prefix', 'asn']
        for param in required_params:
            if not req.has_param(param):
                raise falcon.HTTPMissingParam(param)

        try:
            parsed_prefix = ipaddress.ip_network(req.get_param('prefix', required=True).strip())
        except ValueError as e:
            raise falcon.HTTPInvalidParam(str(e), 'prefix')

        asn = req.get_param_as_int('asn', required=True)

        with self.conn.cursor() as c:
            earliest, latest = get_available_dump_time_range(c)
            if req.has_param('timestamp'):
                timestamp = parse_timestamp(req.get_param('timestamp', required=True), 'timestamp')
                if earliest is None or timestamp < earliest or timestamp > latest:
                    raise falcon.HTTPNotFound(
                        description='Requested timestamp is outside of available data.'
                    )
            else:
                timestamp = latest
                if timestamp is None:
                    raise falcon.HTTPInternalServerError(
                        description='Failed to get latest dump time.'
                    )

            resp.media = get_rpki_status(c, parsed_prefix, timestamp, asn)


class MetadataResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host, dbname=db_dbname, user=db_user, password=db_password, autocommit=True
        )
        self.MAX_PAGE_SIZE = 10000

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return a list of dump timestamps and associated metadata."""
        # We construct the query dynamically depending on which parameters the user specified.
        query_parts = [
            sql.SQL(
                'SELECT dump_time, ingest_time, deleted_vrps, unchanged_vrps, new_vrps, vp, vp_type FROM metadata_view '
            )
        ]
        # Parameters for the SQL query. Length needs to match the number of
        # sql.Placeholder() instances we added in query_parts.
        query_parameters = list()
        # Gather parameters for the URI pointing to the next page.
        uri_parameters = list()
        connector = sql.SQL('WHERE ')
        timestamp_start = None
        timestamp_end = None
        if req.has_param('timestamp__gte'):
            timestamp_gte_param = req.get_param('timestamp__gte', required=True)
            timestamp_start = parse_timestamp(timestamp_gte_param, 'timestamp__gte')
            query_parts.append(connector)
            query_parts.append(sql.SQL('dump_time >= {} ').format(sql.Placeholder()))
            query_parameters.append(timestamp_start)
            uri_parameters.append(f'timestamp__gte={timestamp_gte_param}')
            connector = sql.SQL('AND ')
        if req.has_param('timestamp__lte'):
            timestamp_lte_param = req.get_param('timestamp__lte', required=True)
            timestamp_end = parse_timestamp(
                req.get_param('timestamp__lte', required=True), 'timestamp__lte'
            )
            query_parts.append(connector)
            query_parts.append(sql.SQL('dump_time <= {} ').format(sql.Placeholder()))
            query_parameters.append(timestamp_end)
            uri_parameters.append(f'timestamp__lte={timestamp_lte_param}')

        if timestamp_start and timestamp_end and timestamp_end < timestamp_start:
            raise falcon.HTTPBadRequest(description='Requested end time is before start time.')

        page_size = self.MAX_PAGE_SIZE
        if req.has_param('page_size'):
            page_size = req.get_param_as_int(
                'page_size', required=True, min_value=1, max_value=self.MAX_PAGE_SIZE
            )
        page = 1
        if req.has_param('page'):
            page = req.get_param_as_int('page', required=True, min_value=1)
        query_parts.append(
            sql.SQL('ORDER BY dump_time LIMIT {} OFFSET {}').format(
                sql.Placeholder(), sql.Placeholder()
            )
        )
        query_parameters.append(page_size)
        query_parameters.append((page - 1) * page_size)
        uri_parameters.append(f'page_size={page_size}')
        uri_parameters.append(f'page={page + 1}')

        with self.conn.cursor() as c:
            c.execute(sql.Composed(query_parts), query_parameters)
            formatted_results = [
                {
                    'dump_timestamp': e[0].isoformat(),
                    'ingest_timestamp': e[1].isoformat(),
                    'deleted_vrps': e[2],
                    'unchanged_vrps': e[3],
                    'new_vrps': e[4],
                    'vp': e[5],
                    'vp_type': e[6],
                }
                for e in c.fetchall()
            ]
            # Only return a next URI if there are results left.
            # This creates one unnecessary next_uri if the last page fits the
            # remaining results exactly, but better than nothing.
            next_uri = ''
            if len(formatted_results) == page_size:
                next_uri = falcon.uri.encode(f'{req.uri}?' + '&'.join(uri_parameters))
            resp.media = {'next': next_uri, 'results': formatted_results}


class LatestMetadataResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host, dbname=db_dbname, user=db_user, password=db_password, autocommit=True
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return the earliest and latest imported dump times as well as an
        estimate of the number of processed CCR files in the latest
        rpkispool."""
        with self.conn.cursor() as c:
            earliest, latest = get_available_dump_time_range(c)
            if earliest is None or latest is None:
                resp.media = {'earliest': None, 'latest': None, 'processed_ccr_files': 0}
                return
            check_interval_start = latest - timedelta(days=1)
            c.execute(
                """
                SELECT COUNT(*)
                FROM metadata_view
                WHERE dump_time >= %s
            """,
                (check_interval_start,),
            )
            processed_ccr_files = next(c)[0]
        resp.media = {
            'earliest': earliest.isoformat(),
            'latest': latest.isoformat(),
            'processed_ccr_files': processed_ccr_files,
        }


def default_sink(req: falcon.Request, resp: falcon.Response, **kwargs):
    """Redirect all unknown paths to the documentation."""
    raise falcon.HTTPMovedPermanently(f'{custom_location}/docs')


application = falcon.App(cors_enable=True, sink_before_static_route=False)
application.req_options.strip_url_path_trailing_slash = True
application.add_route(f'{custom_location}/vrp', VRPResource())
application.add_route(f'{custom_location}/status', StatusResource())
application.add_route(f'{custom_location}/metadata', MetadataResource())
application.add_route(f'{custom_location}/metadata/latest', LatestMetadataResource())

swagger_parameters = {
    'deepLinking': 'false',
    'defaultModelsExpandDepth': -1,
    'layout': '"BaseLayout"',
    'presets': '[SwaggerUIBundle.presets.apis]',
}
falcon_api_doc(
    application,
    parameters=swagger_parameters,
    config_path='/app/html/openapi.yaml',
    url_prefix=f'{custom_location}/docs',
    title='RPKI History API',
)
application.add_sink(default_sink)
