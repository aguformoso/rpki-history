import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import logging
import os
import subprocess as sp
import sys
from collections import defaultdict, namedtuple
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime, timedelta

import psycopg
import psycopg.sql
import requests
from bs4 import BeautifulSoup
from psycopg.types.range import Range

vrp_tuple_fields = ['prefix', 'asn', 'max_length']
VRP = namedtuple('VRP', vrp_tuple_fields)

DEFAULT_RPKIVIEWS_HOST = 'dango.attn.jp'
RPKISPOOL_MIRRORS = ['dango.attn.jp', 'rpkiviews.kerfuffle.net', 'josephine.sobornost.net']
HTTP_REQUEST_TIMEOUT_S = 60


class RPKIHistory:
    def __init__(self) -> None:
        self.db_host = os.environ['POSTGRES_HOST']
        self.db_dbname = os.environ['POSTGRES_DB']
        self.db_user = os.environ['POSTGRES_USER']
        with open('/run/secrets/postgres-pw', 'r') as f:
            self.db_password = f.read()
        # Format of URL (excluding file) for use with datetime.str[fp]time.
        self.url_fmt = ''
        # Format of file name for use with datetime.str[fp]time.
        self.file_fmt = ''
        # The name of the vantage point.
        self.vp_name = ''
        # The vantage point type (e.g., full_snapshot)
        self.vp_type = ''
        # The URL of the newest file.
        self.new_file_url = ''
        # The content of the newest file (after download).
        self.new_file_content = b''
        # The datetime of the newest file.
        self.new_ts = None
        # The datetime of the latest available data in the database.
        self.latest_ts = None
        # Map of VRP to (ID [database], visible time range [as psycopg Range]) tuple.
        self.latest_vrps: dict[VRP, tuple[int, Range]] = dict()
        # Set of VRPs contained in the current file.
        self.new_vrps: set[VRP] = set()

    def __enter__(self):
        self.conn = psycopg.connect(
            host=self.db_host, dbname=self.db_dbname, user=self.db_user, password=self.db_password
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.conn.rollback()
        self.conn.close()

    def init_db(self):
        """Initialize the database by creating the required tables and a read-only
        user.
        """
        db_ro_user = os.environ['POSTGRES_RO_USER']
        with open('/run/secrets/postgres-ro-pw', 'r') as f:
            db_ro_password = f.read()
        with self.conn.cursor() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS vrps (
                id bigserial PRIMARY KEY,
                prefix cidr NOT NULL,
                asn bigint NOT NULL,
                max_length integer NOT NULL,
                visible tstzrange NOT NULL,
                UNIQUE (prefix, asn, max_length, visible))
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS vp_types (
                id serial PRIMARY KEY,
                vp_type_name text NOT NULL)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS vps (
                id serial PRIMARY KEY,
                vp_name text NOT NULL,
                vp_type_id integer NOT NULL REFERENCES vp_types)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id serial PRIMARY KEY,
                dump_time timestamp (0) with time zone NOT NULL,
                ingest_time timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
                deleted_vrps integer NOT NULL,
                unchanged_vrps integer NOT NULL,
                new_vrps integer NOT NULL,
                vp_id integer NOT NULL REFERENCES vps)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS dump_time_range (
                id integer PRIMARY KEY,
                earliest timestamp (0) with time zone NOT NULL,
                latest timestamp (0) with time zone NOT NULL)
            """)
            c.execute("""
            CREATE OR REPLACE VIEW metadata_view AS
            SELECT dump_time, ingest_time, deleted_vrps, unchanged_vrps, new_vrps, vp_name AS vp, vp_type_name AS vp_type
            FROM metadata
            JOIN vps ON metadata.vp_id = vps.id
            JOIN vp_types ON vps.vp_type_id = vp_types.id
            """)
            c.execute(
                psycopg.sql.SQL("""
            CREATE ROLE {}
            LOGIN
            PASSWORD {}
            """).format(psycopg.sql.Identifier(db_ro_user), psycopg.sql.Literal(db_ro_password))
            )
            c.execute("""
            GRANT SELECT ON vrps, metadata_view, dump_time_range TO rpki_ro
            """)
        self.conn.commit()

    def insert_or_update_latest_dump_ts(self, c: psycopg.Cursor) -> None:
        """Update the latest dump time or initialize the table row if it not exists."""
        # This table only has one row.
        if self.latest_ts:
            c.execute(
                """
                UPDATE dump_time_range
                SET latest = %s
                WHERE id = 1
            """,
                (self.new_ts,),
            )
        else:
            # No entry yet, initialize with one range.
            c.execute(
                """
                INSERT INTO dump_time_range
                VALUES (1, %s, %s)
            """,
                (self.new_ts, self.new_ts),
            )

    def get_latest_dump_ts(self, c: psycopg.Cursor) -> None:
        """Get the available dump time ranges from the database."""
        c.execute('SELECT latest FROM dump_time_range')
        res = c.fetchone()
        if res is not None:
            self.latest_ts = res[0]
        logging.info(f'Latest dump timestamp: {self.latest_ts}')

    def rows_to_vrp(self, c: psycopg.Cursor) -> dict:
        """Transform the result set of the cursor to a map of VRP -> (id, visible)."""
        if c.description is None:
            return dict()
        # To be robust against changes in the database schema and/or reordering of
        # columns, use a index map.
        cn_idx = {column.name: idx for idx, column in enumerate(c.description)}
        return {
            VRP(*[e[cn_idx[column_name]] for column_name in vrp_tuple_fields]): (
                e[cn_idx['id']],
                e[cn_idx['visible']],
            )
            for e in c.fetchall()
        }

    def get_latest_vrps(self, c: psycopg.Cursor) -> None:
        """Get the set of latest available VRPs from the database (if any)."""
        if self.latest_ts is None:
            return

        c.execute(
            """
            SELECT * FROM vrps
            WHERE visible @> %s
        """,
            (self.latest_ts,),
        )
        self.latest_vrps = self.rows_to_vrp(c)
        logging.info(f'Loaded {len(self.latest_vrps)} VRPs from database')

    def get_or_create_vp_type_id(self, c: psycopg.Cursor) -> int:
        """Get the id of the specified VP type or create new id if none exists."""
        c.execute(
            """
        SELECT id FROM vp_types
        WHERE vp_type_name = %s
        """,
            (self.vp_type,),
        )
        type_id = c.fetchone()
        if type_id is not None:
            return type_id[0]
        c.execute(
            """
        INSERT INTO vp_types (vp_type_name)
        VALUES (%s)
        RETURNING id
        """,
            (self.vp_type,),
        )
        return next(c)[0]

    def get_or_create_vp_id(self, c: psycopg.Cursor) -> int:
        """Get the id of the specified VP or create new id if none exists."""
        c.execute(
            """
        SELECT id FROM vps
        WHERE vp_name = %s
        """,
            (self.vp_name,),
        )
        vp_id = c.fetchone()
        if vp_id is not None:
            return vp_id[0]

        vp_type_id = self.get_or_create_vp_type_id(c)
        c.execute(
            """
        INSERT INTO vps (vp_name, vp_type_id)
        VALUES (%s, %s)
        RETURNING id
        """,
            (self.vp_name, vp_type_id),
        )
        return next(c)[0]

    def insert_metadata(
        self,
        c: psycopg.Cursor,
        deleted_vrps: int,
        unchanged_vrps: int,
        insert_vrps: int,
    ) -> None:
        vp_id = self.get_or_create_vp_id(c)
        c.execute(
            """
            INSERT INTO metadata (dump_time, deleted_vrps, unchanged_vrps, new_vrps, vp_id)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (self.new_ts, deleted_vrps, unchanged_vrps, insert_vrps, vp_id),
        )

    def confirm_dump_exists(self, ts: datetime):
        with self.conn.cursor() as c:
            c.execute(
                """
            SELECT id
            FROM metadata
            WHERE dump_time = %s
            """,
                (ts,),
            )
            res = c.fetchone()
            return res is not None

    def delete_newer_ranges(self, ts: datetime):
        with self.conn.cursor() as c:
            c.execute(
                """
            DELETE FROM vrps
            WHERE %s << visible
            """,
                (Range(None, ts, bounds='(]'),),
            )
            logging.info(f'Deleted {c.rowcount} VRP entries.')

    def delete_newer_metadata(self, ts: datetime):
        with self.conn.cursor() as c:
            c.execute(
                """
            DELETE FROM metadata
            WHERE dump_time > %s
            """,
                (ts,),
            )
            logging.info(f'Deleted {c.rowcount} metadata entries.')

    def update_upper_bound(self, ts: datetime):
        with self.conn.cursor() as c:
            c.execute(
                """
            SELECT id, visible
            FROM vrps
            WHERE NOT upper_inf(visible)
            AND visible @> %s
            """,
                (ts,),
            )
            updated_rows = [(Range(r[1].lower, None), r[0]) for r in c.fetchall()]
            logging.info(f'Setting upper bound to infinity for {len(updated_rows)} rows.')
            c.executemany(
                """      
            UPDATE vrps
            SET visible = %s
            WHERE id = %s
            """,
                updated_rows,
            )

    def reset_latest_dump_time(self, ts: datetime):
        logging.info(f'Setting latest dump time to {ts}')
        with self.conn.cursor() as c:
            c.execute(
                """
            UPDATE dump_time_range
            SET latest = %s
            WHERE id = 1
            """,
                (ts,),
            )

    def reset_sequence_ids(self):
        with self.conn.cursor() as c:
            c.execute('SELECT max(id) FROM vrps')
            max_vrp_id = next(c)[0] + 1
            print(f'Setting VRP sequence id to {max_vrp_id}')
            c.execute(
                psycopg.sql.SQL("""
            ALTER SEQUENCE vrps_id_seq
            RESTART {}
            """).format(psycopg.sql.Literal(max_vrp_id))
            )
            c.execute('SELECT max(id) FROM metadata')
            max_metadata_id = next(c)[0] + 1
            print(f'Setting metadata sequence id to {max_metadata_id}')
            c.execute(
                psycopg.sql.SQL("""
            ALTER SEQUENCE metadata_id_seq
            RESTART {}
            """).format(psycopg.sql.Literal(max_metadata_id))
            )

    def reset_db_to_timestamp(self, ts: datetime) -> None:
        # Let x be the time we want to reset the database to and y the currently
        # latest dump time.
        # To reset the database to time x, we require the following actions:
        #
        #   1. Delete ranges starting after x.
        #   2. Set the upper bound of ranges containing x to infinity.
        #   3. Set the latest dump time to x.
        #   4. Delete metadata rows for dumps newer than x.
        #   5. Set metadata and vrp id sequences to the maximum value after
        #      deletion.
        #
        # The processing at time x performed the following actions:
        #
        #   1. If a VRP disappeared, set its upper bound to time x - 1, i.e.,
        #      the time of the previous dump.
        #   2. If a VRP appeared, create a new range [x, infinity).
        #   3. If a VRP remains visible, do nothing, i.e., leave range at
        #      [x - n, infinity).
        #
        # Thus, if a range is currently [x - n, infinity), including n = 0
        # (newly created ranges), the VRP never disappeared between x - n and y
        # and thus we can leave the range as-is.
        # If a range contains x and has an upper bound != infinity (including
        # [x, x]), the upper bound was set by a dump newer than x. We revert
        # this action by setting the upper bound to infinity.
        # Finally, ranges with a start time newer than x can be deleted as they
        # were created by newer dumps.
        if not self.confirm_dump_exists(ts):
            logging.error('Cannot reset database. Specified dump timestamp not found in metadata.')
            return
        self.delete_newer_ranges(ts)
        self.update_upper_bound(ts)
        self.reset_latest_dump_time(ts)
        self.delete_newer_metadata(ts)
        self.reset_sequence_ids()
        self.conn.commit()

    def update_db(self, timestamp: datetime | None = None):
        """Update the database with data for the specified timestamp, or the newest data
        if available and no timestamp is specified.
        """
        with self.conn.cursor() as c:
            self.get_latest_dump_ts(c)

            # Fetch new VRPs.
            if timestamp:
                self.fetch_and_read_specific_file(timestamp)
            else:
                if not self.fetch_and_read_new_file():
                    logging.info('No new data available.')
                    return
            # Get latest VRPs from database.
            self.get_latest_vrps(c)
            self.process_vrps(c)
            self.conn.commit()

    def fetch_and_read_file(self) -> None:
        """Download the file specified by new_file_url and parse its contents."""
        for attempt in range(1, 4):
            logging.info(f'Attempt {attempt}')
            logging.info(f'Fetching file: {self.new_file_url}')
            try:
                r = requests.get(self.new_file_url, timeout=HTTP_REQUEST_TIMEOUT_S)
                r.raise_for_status()
            except (requests.HTTPError, requests.Timeout) as e:
                logging.error(f'Failed to fetch file: {e}')
                continue
            self.new_file_content = r.content
            if self.verify_file_integrity():
                continue
            self.read_file()
            return
        logging.info('Too many failed attempts. Aborting.')
        raise RuntimeError('Too many failed attempts.')

    def fetch_and_read_new_file(self) -> bool:
        """Find the newest available file and process it if it is not already in the
        database.

        Return True if new data is available, False otherwise.
        """
        self.get_new_file_url()
        if not self.new_file_url or (self.latest_ts and self.new_ts <= self.latest_ts):
            return False
        self.fetch_and_read_file()
        return True

    def fetch_and_read_specific_file(self, ts: datetime) -> None:
        """Fetch and process the file with the specified timestamp."""
        self.new_ts = ts
        self.new_file_url = os.path.join(ts.strftime(self.url_fmt), ts.strftime(self.file_fmt))
        self.fetch_and_read_file()

    def process_vrps(self, c: psycopg.Cursor) -> None:
        # Compute differences.
        deleted_vrps = set(self.latest_vrps.keys()) - self.new_vrps
        unchanged_vrps = self.new_vrps.intersection(self.latest_vrps.keys())
        insert_vrps = list(self.new_vrps - self.latest_vrps.keys())  # Fixed order is needed later.

        # Insert metadata for this dump.
        self.insert_metadata(c, len(deleted_vrps), len(unchanged_vrps), len(insert_vrps))
        self.insert_or_update_latest_dump_ts(c)

        # Set upper bound of visible range for deleted VRPs.
        delete_data = list()
        for vrp in deleted_vrps:
            vrp_id, visible_range = self.latest_vrps.pop(vrp)
            delete_data.append((Range(visible_range.lower, self.latest_ts, bounds='[]'), vrp_id))
        logging.info(f'Setting upper bound of visible range for {len(delete_data)} VRPs')
        c.executemany(
            """
            UPDATE vrps
            SET visible = %s
            WHERE id = %s
        """,
            delete_data,
        )

        # Insert new VRPs.
        insert_data = [
            (vrp.prefix, vrp.asn, vrp.max_length, Range(lower=self.new_ts, bounds='[)'))
            for vrp in insert_vrps
        ]
        logging.info(f'Inserting {len(insert_data)} new VRPs')
        c.executemany(
            """
            INSERT INTO vrps (prefix, asn, max_length, visible)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """,
            insert_data,
            returning=True,
        )
        for idx, _ in enumerate(c.results()):
            vrp_id = next(c)[0]
            prefix, asn, max_length, visible_range = insert_data[idx]
            self.latest_vrps[VRP(prefix, asn, max_length)] = (vrp_id, visible_range)

    def verify_file_integrity(self) -> bool:
        # Default is no verification, i.e., never raise an error.
        return False

    def get_new_file_url(self) -> None:
        raise NotImplementedError()

    def read_file(self) -> None:
        raise NotImplementedError()


class RPKIViews(RPKIHistory):
    def __init__(self, rpkiviews_host: str = DEFAULT_RPKIVIEWS_HOST) -> None:
        super().__init__()
        # The set of parsed VRPs from the newest file.
        self.new_vrps = set()
        if not rpkiviews_host.startswith('https://'):
            rpkiviews_host = f'https://{rpkiviews_host}'
        self.vp_name = rpkiviews_host.removeprefix('https://').strip('/')
        self.vp_type = 'full_snapshot'
        self.url_fmt = os.path.join(rpkiviews_host, 'rpkidata/%Y/%m/%d/')
        self.file_fmt = 'rpki-%Y%m%dT%H%M%SZ.tgz'

    def get_datetime_from_filename(self, fname: str) -> datetime:
        return datetime.strptime(fname, self.file_fmt).replace(tzinfo=UTC)

    def verify_file_integrity(self) -> bool:
        logging.info('Verifying file integrity.')
        fname = os.path.basename(self.new_file_url)
        hash_file_url = os.path.join(os.path.dirname(self.new_file_url), 'SHA256')
        try:
            r = requests.get(hash_file_url, timeout=HTTP_REQUEST_TIMEOUT_S)
            r.raise_for_status()
        except (requests.HTTPError, requests.Timeout) as e:
            logging.error(f'Failed to fetch SHA256 file: {e}')
            return True
        checksum_file_lines = 0
        for line in r.text.splitlines():
            line_split = line.split()
            if len(line_split) != 4:
                logging.warning(f'Ignoring invalid SHA256 line: {line}')
                continue
            checksum_file_lines += 1
            line_fname = line_split[1].strip('()')
            if line_fname != fname:
                continue
            expected_checksum = line_split[3]
            break
        else:
            logging.error(
                f'Failed to find checksum for this file. Parsed {checksum_file_lines} lines in checksum '
                'file.'
            )
            return True
        logging.info(f'Expected checksum: {expected_checksum}')
        actual_checksum = base64.b64encode(hashlib.sha256(self.new_file_content).digest()).decode()
        logging.info(f'  Actual checksum: {actual_checksum}')
        if actual_checksum == expected_checksum:
            logging.info('Verification OK')
            return False
        logging.info('Verification FAIL')
        return True

    def get_new_file_url(self) -> None:
        """Get the URL of the newest available file."""
        curr_ts = datetime.now(tz=UTC)
        folder_url = curr_ts.strftime(self.url_fmt)
        logging.info(f'Looking for recent file at {folder_url}')
        try:
            r = requests.get(folder_url, timeout=HTTP_REQUEST_TIMEOUT_S)
        except requests.Timeout as e:
            logging.error(f'Timed out waiting for request: {e}')
            return
        # If we are just after midnight UTC, we should look at the previous day.
        if r.status_code == 404:
            curr_ts -= timedelta(hours=24)
            folder_url = curr_ts.strftime(self.url_fmt)
            logging.info(f'Looking for recent file at {folder_url}')
            try:
                r = requests.get(folder_url, timeout=HTTP_REQUEST_TIMEOUT_S)
                r.raise_for_status()
            except (requests.HTTPError, requests.Timeout) as e:
                logging.error(f'Failed to get latest file: {e}')
                return

        soup = BeautifulSoup(r.text, features='html.parser')
        new_file = ''
        for link in soup.find_all('a'):
            href = link['href']
            if not href.startswith('rpki-'):
                continue

            file_ts = self.get_datetime_from_filename(href)
            if self.new_ts is None or file_ts > self.new_ts:
                self.new_ts = file_ts
                new_file = href

        if not new_file:
            logging.error(f'Failed to find valid file in folder: {folder_url}')
            return

        self.new_file_url = os.path.join(folder_url, new_file)

    def read_file(self) -> None:
        """Read the contents of the downloaded file and parse VRP entries."""
        logging.info('Reading file')
        base = os.path.basename(self.new_file_url).removesuffix('.tgz')
        member = f'{base}/output/rpki-client.csv'
        ps = sp.run(
            ['tar', '--extract', '--gzip', '--to-stdout', '--file', '-', member],
            input=self.new_file_content,
            stdout=sp.PIPE,
            check=True,
        )

        for l in csv.DictReader(ps.stdout.decode().splitlines()):
            asn = int(l['ASN'].removeprefix('AS'))
            prefix = ipaddress.ip_network(l['IP Prefix'])
            max_length = int(l['Max Length'])
            self.new_vrps.add(VRP(prefix, asn, max_length))
        logging.info(f'Read {len(self.new_vrps)} unique VRPs from file')


class RPKISpool(RPKIHistory):
    def __init__(self, rpkispool_mirror: str = '', vp: str = '', num_workers: int = 4) -> None:
        super().__init__()
        self.vp_name = vp
        self.vp_type = 'rpkispool'
        self.num_workers = num_workers
        if rpkispool_mirror:
            # Do not autoselect mirror.
            logging.info(f'Using mirror {rpkispool_mirror}')
            self.__set_mirror(rpkispool_mirror.removeprefix('https://'))
        self.file_fmt = '%Y%m%d-rpkispool.tar.zst'
        self.ccr_files: list[tuple[datetime, str]] = list()

    def __set_mirror(self, mirror: str) -> None:
        self.url_fmt = os.path.join(f'https://{mirror}', 'rpkidata/rpkispools/%Y/%m/%d/')

    def __mirror_set(self) -> bool:
        return self.url_fmt != ''

    @staticmethod
    def __probe_file_exists(url: str) -> bool:
        logging.info(f'Probing file {url}')
        try:
            r = requests.head(url, timeout=60)
        except (requests.Timeout, requests.ConnectionError) as e:
            logging.warning(f'Request failed: {e}')
            return False
        if r.status_code == 200:
            return True
        logging.warning(f'Request failed with status code {r.status_code}')
        return False

    def __probe_mirrors(self, ts) -> bool:
        for host in RPKISPOOL_MIRRORS:
            self.__set_mirror(host)
            url = ts.strftime(os.path.join(self.url_fmt, self.file_fmt))
            if self.__probe_file_exists(url):
                logging.info(f'Using {host} as mirror.')
                return False
        logging.warning('Failed to find file at any mirror.')
        return True

    def get_new_file_url(self) -> None:
        if self.latest_ts is None:
            logging.error(
                'rpkispool worker needs at least one existing dump to derive next '
                'timestamp. Run with specified timestamp once to initialize.'
            )
            return
        expected_timestamp = self.latest_ts + timedelta(days=1)
        if not self.__mirror_set():
            if self.__probe_mirrors(expected_timestamp):
                # New file not found at any mirror.
                return
            self.new_file_url = expected_timestamp.strftime(
                os.path.join(self.url_fmt, self.file_fmt)
            )
        else:
            url = expected_timestamp.strftime(os.path.join(self.url_fmt, self.file_fmt))
            if not self.__probe_file_exists(url):
                return
            self.new_file_url = url
        # Set this for check in fetch_and_read_new_file() to pass, even though
        # it will be overwritten with the actual timestamps of the individual
        # CCR files later.
        self.new_ts = expected_timestamp

    def find_best_vp(self, spool_file: str):
        try:
            p = sp.run(
                ['tar', '-t', '--zstd', '--wildcards', '*.ccr', '-f', spool_file],
                stdout=sp.PIPE,
                check=True,
            )
        except sp.CalledProcessError as e:
            logging.error(f'Error while probing CCR files: {e}')
            return
        ccrs = p.stdout.decode().splitlines()
        logging.info(f'Found {len(ccrs)} CCR files in total.')
        vp_counts = defaultdict(int)
        for ccr in ccrs:
            vp = os.path.basename(ccr).removesuffix('.ccr').split('-')[1]
            vp_counts[vp] += 1
        vp_counts_sorted = sorted(vp_counts.items(), key=lambda t: -t[1])
        best_vp, ccr_count = vp_counts_sorted[0]
        logging.info(f'Using VP {best_vp} with {ccr_count} CCR files.')
        self.vp_name = best_vp

    def read_file(self) -> None:
        working_dir = '/tmp'
        ccr_dir = os.path.join(working_dir, 'ccrs')
        spool_file = os.path.join(working_dir, 'spool.tar.zst')

        os.makedirs(ccr_dir, exist_ok=True)
        logging.info(f'Writing spool to {spool_file}')
        with open(spool_file, 'wb') as f:
            f.write(self.new_file_content)
        self.new_file_content = b''
        if not self.vp_name:
            self.find_best_vp(spool_file)
            if not self.vp_name:
                # Error while finding best VP.
                return
        logging.info(f'Extracting {self.vp_name} CCR files to {ccr_dir}')
        try:
            sp.run(
                [
                    'tar',
                    '-C',
                    ccr_dir,
                    '-x',
                    '--zstd',
                    '--wildcards',
                    f'*{self.vp_name}.ccr',
                    '--strip-components',
                    '3',
                    '-f',
                    spool_file,
                ],
                check=True,
            )
        except sp.CalledProcessError as e:
            logging.error(f'Error during CCR extraction: {e}')
            return

        for entry in os.scandir(ccr_dir):
            if not entry.is_file() or not entry.name.endswith('.ccr'):
                continue
            ccr_dt = datetime.strptime(entry.name, f'%Y%m%dT%H%M%SZ-{self.vp_name}.ccr').replace(
                tzinfo=UTC
            )
            self.ccr_files.append((ccr_dt, os.path.join(ccr_dir, entry.name)))
        self.ccr_files.sort()

    @staticmethod
    def parse_ccr_worker(params: tuple[datetime, str]) -> tuple[datetime, str, set[VRP]]:
        ccr_dt, ccr_file = params
        logging.info(f'Worker: {ccr_file} start')
        vrps: list[VRP] = []
        with sp.Popen(
            f"rpki-client -d . -j -f {ccr_file} | jq --compact-output '.roapayload_state.vrps[]'",
            shell=True,
            text=True,
            stdout=sp.PIPE,
            stderr=sp.DEVNULL,
        ) as p:
            for vrp_line in p.stdout:
                try:
                    vrp = json.loads(vrp_line)
                    prefix = ipaddress.ip_network(vrp['prefix'])
                    if 'maxlen' in vrp:
                        vrps.append(VRP(prefix, vrp['asn'], vrp['maxlen']))
                    else:
                        vrps.append(VRP(prefix, vrp['asn'], prefix.prefixlen))
                except (json.JSONDecodeError, ValueError) as e:
                    logging.error(f'Failed to parse VRP "{vrp_line.strip()}": {e}')
                    return ccr_dt, ccr_file, set()
        logging.info(f'Worker: {ccr_file} done')
        return ccr_dt, ccr_file, set(vrps)

    def update_db(self, timestamp: datetime | None = None) -> None:
        """Update the database with data for the specified timestamp, or the newest data
        if available and no timestamp is specified.
        """
        with self.conn.cursor() as c:
            self.get_latest_dump_ts(c)

            # Fetch new VRPs
            if timestamp:
                if not self.__mirror_set() and self.__probe_mirrors(timestamp):
                    logging.error('No file for requested timestamp exists.')
                    return
                self.new_ts = timestamp
                self.new_file_url = os.path.join(
                    timestamp.strftime(self.url_fmt), timestamp.strftime(self.file_fmt)
                )
                with open('/tmp/spool.tar.zst', 'rb') as f:
                    self.new_file_content = f.read()
                self.read_file()
                # self.fetch_and_read_specific_file(timestamp)
            else:
                if not self.fetch_and_read_new_file():
                    return
            # Get latest VRPs from database.
            self.get_latest_vrps(c)
            with ProcessPoolExecutor(max_workers=self.num_workers) as p:
                for ccr_dt, fname, vrps in p.map(self.parse_ccr_worker, self.ccr_files):
                    logging.info(f'CCR File: {fname} VRPs: {len(vrps)}')
                    self.new_ts = ccr_dt
                    if not vrps:
                        self.conn.rollback()
                        return
                    self.new_vrps = vrps
                    self.process_vrps(c)
                    self.latest_ts = ccr_dt
                    logging.info('Done')
            self.conn.commit()


if __name__ == '__main__':
    handlers = [logging.StreamHandler(sys.stdout)]
    if os.path.exists('/log'):
        handlers.append(logging.FileHandler('/log/rpki-history.log'))
    FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(
        format=FORMAT,
        level=logging.INFO,
        handlers=handlers,
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.info(f'Started: {sys.argv}')
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'update', 'reset'])
    parser.add_argument(
        '-t',
        '--timestamp',
        help='(update) fetch file for specific timestamp (reset) reset database to this timestamp '
        '[YYYYMMDDThhmmss]',
    )
    parser.add_argument(
        '-m',
        '--mode',
        choices=['rpkiviews', 'rpkispool'],
        default='rpkispool',
        help='data source',
    )
    parser.add_argument('--mirror', help='mirror to use', default='')
    parser.add_argument('--vantage-point', help='(rpkispool) vantage point to use', default='')
    parser.add_argument(
        '-n',
        '--num-workers',
        help='(rpkispool) number of parallel CCR parsers',
        default=4,
        type=int,
    )
    args = parser.parse_args()
    mode = args.mode
    mirror = args.mirror
    match mode:
        case 'rpkiviews':
            if mirror:
                rpki = RPKIViews(mirror)
            else:
                rpki = RPKIViews()
        case 'rpkispool':
            rpki = RPKISpool(args.mirror, args.vantage_point, args.num_workers)
    command = args.command
    match command:
        case 'init':
            with rpki:
                rpki.init_db()
        case 'update':
            timestamp = None
            if args.timestamp:
                try:
                    timestamp = datetime.strptime(args.timestamp, '%Y%m%dT%H%M%S').replace(
                        tzinfo=UTC
                    )
                except ValueError as e:
                    logging.error(f'Invalid timestamp specified: {args.timestamp} ({e})')
                    sys.exit(1)
            with rpki:
                rpki.update_db(timestamp)
        case 'reset':
            timestamp = args.timestamp
            if timestamp is None:
                logging.error('Timestamp argument is required for reset.')
                sys.exit(1)
            try:
                timestamp = datetime.strptime(args.timestamp, '%Y%m%dT%H%M%S').replace(tzinfo=UTC)
            except ValueError as e:
                logging.error(f'Invalid timestamp specified: {args.timestamp} ({e})')
                sys.exit(1)
            with rpki:
                rpki.reset_db_to_timestamp(timestamp)
    logging.info('Done')
    sys.exit(0)
