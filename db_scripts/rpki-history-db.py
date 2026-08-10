import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import logging
import lzma
import os
import subprocess as sp
import sys
from collections import namedtuple
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

import pandas as pd
import psycopg
import psycopg.sql
import requests
from bs4 import BeautifulSoup
from psycopg.types.range import Range

vrp_tuple_fields = ['prefix', 'asn', 'max_length']
VRP = namedtuple('VRP', vrp_tuple_fields)

RPKIVIEWS_HOST = 'https://dango.attn.jp'
RIPENCC_HOST = 'https://ftp.ripe.net'
RPKIFLUTTER_VP = 'routinator-3.rpki.ripe.net'


class RPKIHistory:
    def __init__(self) -> None:
        self.db_host = os.environ['POSTGRES_HOST']
        self.db_dbname = os.environ['POSTGRES_DB']
        self.db_user = os.environ['POSTGRES_USER']
        with open('/run/secrets/postgres-pw', 'r') as f:
            self.db_password = f.read()
        self.url_fmt = str()
        self.file_fmt = str()
        # The URL of the newest file.
        self.new_file_url = str()
        # The content of the newest file (after download).
        self.new_file_content = bytes()
        # The datetime of the newest file.
        self.new_ts = None
        # The datetime of the latest available data in the database.
        self.latest_ts = None
        # Map of VRP to (ID [database], visible time range [as psycopg Range]) tuple.
        self.latest_vrps = dict()

    def __enter__(self):
        self.conn = psycopg.connect(
            host=self.db_host,
            dbname=self.db_dbname,
            user=self.db_user,
            password=self.db_password
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
                prefix cidr,
                asn bigint,
                max_length integer,
                visible tstzrange)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id serial PRIMARY KEY,
                dump_time timestamp (0) with time zone,
                ingest_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
                deleted_vrps integer,
                unchanged_vrps integer,
                new_vrps integer)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS dump_time_range (
                id integer PRIMARY KEY,
                earliest timestamp (0) with time zone,
                latest timestamp (0) with time zone)
            """)
            c.execute(psycopg.sql.SQL("""
            CREATE ROLE {}
            LOGIN
            PASSWORD {}
            """).format(
                psycopg.sql.Identifier(db_ro_user),
                psycopg.sql.Literal(db_ro_password)))
            c.execute("""
            GRANT SELECT ON vrps, metadata, dump_time_range TO rpki_ro
            """)
        self.conn.commit()

    def insert_or_update_latest_dump_ts(self, c: psycopg.Cursor, ts: datetime) -> None:
        """Update the latest dump time or initialize the table row if it not exists."""
        # This table only has one row.
        if self.latest_ts:
            c.execute("""
                UPDATE dump_time_range
                SET latest = %s
                WHERE id = 1
            """, (ts, ))
        else:
            # No entry yet, initialize with one range.
            c.execute("""
                INSERT INTO dump_time_range
                VALUES (1, %s, %s)
            """, (ts, ts))

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
            VRP(
                *[e[cn_idx[column_name]]
                  for column_name in vrp_tuple_fields]
            ):
            (e[cn_idx['id']], e[cn_idx['visible']])
            for e in c.fetchall()
        }

    def get_latest_vrps(self, c: psycopg.Cursor) -> None:
        """Get the set of latest available VRPs from the database (if any)."""
        if self.latest_ts is None:
            return

        c.execute("""
            SELECT * FROM vrps
            WHERE visible @> %s
        """, (self.latest_ts, ))
        self.latest_vrps = self.rows_to_vrp(c)
        logging.info(f'Loaded {len(self.latest_vrps)} VRPs from database')

    def update_db(self, timestamp: datetime = None):
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
            r = requests.get(self.new_file_url)
            try:
                r.raise_for_status()
            except requests.HTTPError as e:
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
        self.new_file_url = os.path.join(
            ts.strftime(self.url_fmt),
            ts.strftime(self.file_fmt)
        )
        self.fetch_and_read_file()

    def verify_file_integrity(self) -> bool:
        # Default is no verification, i.e., never raise an error.
        return False

    def get_new_file_url(self) -> None:
        raise NotImplementedError()

    def read_file(self) -> None:
        raise NotImplementedError()

    def process_vrps(self, c: psycopg.Cursor) -> None:
        raise NotImplementedError()


class RPKIViews(RPKIHistory):
    def __init__(self) -> None:
        super().__init__()
        # The set of parsed VRPs from the newest file.
        self.new_vrps = set()
        self.url_fmt = os.path.join(RPKIVIEWS_HOST, 'rpkidata/%Y/%m/%d/')
        self.file_fmt = 'rpki-%Y%m%dT%H%M%SZ.tgz'

    def get_datetime_from_filename(self, fname: str) -> datetime:
        return datetime.strptime(fname, self.file_fmt).replace(tzinfo=timezone.utc)

    def verify_file_integrity(self) -> bool:
        logging.info('Verifying file integrity.')
        fname = os.path.basename(self.new_file_url)
        hash_file_url = os.path.join(os.path.dirname(self.new_file_url), 'SHA256')
        r = requests.get(hash_file_url)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            logging.error(f'Failed to fetch SHA256 file: {e}')
            return True
        expected_checksum = str()
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
            logging.error(f'Failed to find checksum for this file. Parsed {checksum_file_lines} lines in checksum '
                          'file.')
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
        curr_ts = datetime.now(tz=timezone.utc)
        folder_url = curr_ts.strftime(self.url_fmt)
        r = requests.get(folder_url)
        # If we are just after midnight UTC, we should look at the previous day.
        if r.status_code == 404:
            curr_ts -= timedelta(hours=24)
            folder_url = curr_ts.strftime(self.url_fmt)
            r = requests.get(folder_url)
            try:
                r.raise_for_status()
            except Exception as e:
                logging.error(f'Failed to get latest file: {e}')
                return

        soup = BeautifulSoup(r.text, features='html.parser')
        new_file = str()
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
        # Scripts runs in Alpine-based Docker container.
        ps = sp.run(['tar', 'x', '-z', '-O', '-f', '-', member],
                    input=self.new_file_content,
                    stdout=sp.PIPE,
                    check=True)

        for l in csv.DictReader(ps.stdout.decode().splitlines()):
            asn = int(l['ASN'].removeprefix('AS'))
            prefix = ipaddress.ip_network(l['IP Prefix'])
            max_length = int(l['Max Length'])
            self.new_vrps.add(VRP(prefix, asn, max_length))
        logging.info(f'Read {len(self.new_vrps)} unique VRPs from file')

    def process_vrps(self, c: psycopg.Cursor) -> None:
        # Compute differences.
        deleted_vrps = set(self.latest_vrps.keys()) - self.new_vrps
        unchanged_vrps = self.new_vrps.intersection(self.latest_vrps.keys())
        insert_vrps = self.new_vrps - self.latest_vrps.keys()

        # Insert metadata for this dump.
        c.execute("""
            INSERT INTO metadata (dump_time, deleted_vrps, unchanged_vrps, new_vrps)
            VALUES (%s, %s, %s, %s)
            """, (self.new_ts, len(deleted_vrps), len(unchanged_vrps), len(insert_vrps)))
        self.insert_or_update_latest_dump_ts(c, self.new_ts)

        # Set upper bound of visible range for deleted VRPs.
        delete_data = list()
        for vrp in deleted_vrps:
            vrp_id, visible_range = self.latest_vrps[vrp]
            delete_data.append((Range(visible_range.lower, self.latest_ts, bounds='[]'), vrp_id))
        logging.info(f'Setting upper bound of visible range for {len(delete_data)} VRPs')
        c.executemany("""
            UPDATE vrps
            SET visible = %s
            WHERE id = %s
        """, delete_data)

        # Insert new VRPs.
        insert_data = [
            (vrp.prefix, vrp.asn, vrp.max_length, Range(lower=self.new_ts, bounds='[)'))
            for vrp in insert_vrps
        ]
        logging.info(f'Inserting {len(insert_data)} new VRPs')
        c.executemany("""
            INSERT INTO vrps (prefix, asn, max_length, visible)
            VALUES (%s, %s, %s, %s)
        """, insert_data)


class RIPENCCDaily(RPKIViews):
    """Fetch VRPs from the RIPE NCC RPKI archive at ftp.ripe.net.

    In contrast to RPKIViews, this archive contains exactly one dump per day, stored
    under a YYYY/MM/DD path with the fixed file name roas.csv.xz. Since the file name
    carries no time information, the dump is treated as being taken at midnight UTC of
    its directory date.

    The VRP diffing logic of RPKIViews is reused as-is.
    """

    # Candidate column names per VRP field, in order of preference. The archive has used
    # the RIPE NCC validator header (URI,ASN,IP Prefix,Max Length,Not Before,Not After)
    # for years, but rpki-client and Routinator emit slightly different headers, so
    # resolve columns by name instead of by position.
    CSV_COLUMNS = {
        'asn': ('asn',),
        'prefix': ('ip prefix', 'prefix'),
        'max_length': ('max length', 'maxlength', 'max_length'),
    }

    def __init__(self) -> None:
        super().__init__()
        self.url_fmt = os.path.join(RIPENCC_HOST, 'rpki/ripencc.tal/%Y/%m/%d/')
        self.file_fmt = 'roas.csv.xz'

    def build_file_url(self, ts: datetime) -> str:
        return os.path.join(ts.strftime(self.url_fmt), ts.strftime(self.file_fmt))

    def get_new_file_url(self) -> None:
        """Get the URL of the newest available file.

        The file name is fixed, so there is no need to scrape the directory listing. Try
        the current day first and fall back to the previous day, since the dump for the
        current day is not necessarily published yet.
        """
        curr_ts = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        for ts in (curr_ts, curr_ts - timedelta(days=1)):
            file_url = self.build_file_url(ts)
            r = requests.head(file_url)
            if r.ok:
                self.new_ts = ts
                self.new_file_url = file_url
                return
            logging.info(f'No file available at {file_url} ({r.status_code})')
        logging.error(f'Failed to get latest file for {curr_ts.date()} or the day before.')

    def fetch_and_read_specific_file(self, ts: datetime) -> None:
        """Fetch and process the dump of the day of the specified timestamp.

        Only the date part of the timestamp is significant; the time is normalized to
        midnight UTC so that the recorded dump time matches the automatic path.
        """
        self.new_ts = ts.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        self.new_file_url = self.build_file_url(self.new_ts)
        self.fetch_and_read_file()

    def verify_file_integrity(self) -> bool:
        """Compare the file against its .sha256 sidecar.

        Return True if the file should be discarded, i.e., if verification failed.

        The sidecar uses the coreutils format ("<hex digest>  <file name>"), which
        differs from the base64 SHA256 manifest used by RPKIViews.
        """
        logging.info('Verifying file integrity.')
        hash_file_url = f'{self.new_file_url}.sha256'
        r = requests.get(hash_file_url)
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            logging.error(f'Failed to fetch sha256 file: {e}')
            return True
        line_split = r.text.split()
        if not line_split:
            logging.error(f'Empty sha256 file: {hash_file_url}')
            return True
        expected_checksum = line_split[0].lower()
        logging.info(f'Expected checksum: {expected_checksum}')
        actual_checksum = hashlib.sha256(self.new_file_content).hexdigest()
        logging.info(f'  Actual checksum: {actual_checksum}')
        if actual_checksum == expected_checksum:
            logging.info('Verification OK')
            return False
        logging.info('Verification FAIL')
        return True

    def resolve_csv_columns(self, fieldnames: Sequence[str] | None) -> dict:
        """Map VRP field names to the matching column names of the CSV header."""
        if not fieldnames:
            raise RuntimeError('Missing CSV header.')
        normalized = {name.strip().lower(): name for name in fieldnames if name}
        columns = dict()
        for field, candidates in self.CSV_COLUMNS.items():
            for candidate in candidates:
                if candidate in normalized:
                    columns[field] = normalized[candidate]
                    break
            else:
                raise RuntimeError(f'Failed to find a column for "{field}" in CSV header: {fieldnames}')
        return columns

    def read_file(self) -> None:
        """Read the contents of the downloaded file and parse VRP entries."""
        logging.info('Reading file')
        content = lzma.decompress(self.new_file_content).decode()
        reader = csv.DictReader(content.splitlines())
        columns = self.resolve_csv_columns(reader.fieldnames)
        malformed_lines = 0
        for line in reader:
            try:
                asn = int(line[columns['asn']].removeprefix('AS'))
                prefix = ipaddress.ip_network(line[columns['prefix']])
                max_length = int(line[columns['max_length']])
            except (AttributeError, TypeError, ValueError) as e:
                malformed_lines += 1
                logging.warning(f'Ignoring malformed line: {line} ({e})')
                continue
            self.new_vrps.add(VRP(prefix, asn, max_length))
        if malformed_lines:
            logging.warning(f'Ignored {malformed_lines} malformed lines.')
        if not self.new_vrps:
            raise RuntimeError('Read no VRPs from file.')
        logging.info(f'Read {len(self.new_vrps)} unique VRPs from file')


class RPKIFlutter(RPKIHistory):
    def __init__(self) -> None:
        super().__init__()
        self.url_fmt = 'https://rd-www-1.ripe.net/rpki_flutter/daily/'
        self.file_fmt = 'rpki-flutter.%Y-%m-%d.parquet'
        self.df = pd.DataFrame()

    def get_new_file_url(self) -> None:
        """Get the URL of the newest available file."""
        curr_ts = datetime.now(tz=timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        # The file for the current day is actively updated, so we should only fetch data
        # for the previous day.
        self.new_ts = curr_ts - timedelta(days=1)
        self.new_file_url = os.path.join(self.url_fmt, self.new_ts.strftime(self.file_fmt))

        r = requests.head(self.new_file_url)
        try:
            r.raise_for_status()
        except Exception as e:
            logging.error(f'Failed to get latest file ({self.new_file_url}): {e}')
            return

    def read_file(self) -> None:
        """Read the contents of the downloaded file and parse VRP entries."""
        logging.info('Reading file')
        self.df = pd.read_parquet(io.BytesIO(self.new_file_content),
                                  columns=['type', 'vp', 'capture_ts', 'asn', 'pfx', 'maxlen'])
        self.df = self.df[self.df['vp'] == RPKIFLUTTER_VP]
        self.df['capture_ts'] = pd.to_datetime(self.df['capture_ts'], utc=True, unit='s')
        self.df['asn'] = self.df['asn'].apply(lambda x: int(x.removeprefix('AS')))
        self.df['pfx'] = self.df['pfx'].apply(lambda x: ipaddress.ip_network(x))
        msg_counts = self.df['type'].value_counts()
        state_msg = 0
        announce_msg = 0
        withdraw_msg = 0
        if 'S' in msg_counts:
            state_msg = msg_counts.loc['S']
        if 'A' in msg_counts:
            announce_msg = msg_counts.loc['A']
        if 'W' in msg_counts:
            withdraw_msg = msg_counts.loc['W']
        logging.info(f'Read {len(self.df)} messages from file. {state_msg} state, {announce_msg} announce, '
                     f'{withdraw_msg}, withdraw.')

    def process_vrps(self, c: psycopg.Cursor) -> None:
        # List of VRP rows that need to be updated, i.e., where in the previous dump and
        # got withdrawn.
        update_rows = list()
        # List of new VRP rows that need to be inserted, but already have a complete
        # range (caused by announce and withdraw within one dump).
        insert_rows = list()
        # Map new VRP rows, that need to be inserted, to their visible range (lower
        # bound only).
        insert_vrps = dict()
        # These counters are not totally precise, e.g., if a VRP is announced and
        # withdrawn in one dump.
        num_deleted_vrps = 0
        num_unchanged_vrps = 0
        num_new_vrps = 0
        for row in self.df.itertuples():
            vrp = VRP(row.pfx, row.asn, row.maxlen)
            match row.type:
                # Start state should be the same as the latest dump, but sometimes it
                # includes additional messages.
                case 'S':
                    if vrp not in self.latest_vrps:
                        # Do not print message if there is no initial state yet.
                        if self.latest_vrps:
                            logging.warning(f'Adding VRP from start state even though it was not in the latest dump. '
                                            f'{row}')
                        insert_vrps[vrp] = Range(lower=row.capture_ts, bounds='[)')
                        num_new_vrps += 1
                    else:
                        num_unchanged_vrps += 1
                case 'A':
                    if vrp in self.latest_vrps or vrp in insert_vrps:
                        logging.warning(f'Ignoring duplicate announce: {row}')
                        continue
                    num_new_vrps += 1
                    insert_vrps[vrp] = Range(lower=row.capture_ts, bounds='[)')
                case 'W':
                    if vrp not in self.latest_vrps and vrp not in insert_vrps:
                        logging.warning(f'Withdraw of unknown VRP: {row}')
                        continue
                    num_deleted_vrps += 1
                    if vrp in self.latest_vrps:
                        vrp_id, visible_range = self.latest_vrps.pop(vrp)
                        update_rows.append((Range(visible_range.lower, row.capture_ts, bounds='[]'), vrp_id))
                    else:
                        visible_range = insert_vrps.pop(vrp)
                        insert_rows.append((
                            vrp.prefix,
                            vrp.asn,
                            vrp.max_length,
                            Range(visible_range.lower, row.capture_ts, bounds='[]')
                        ))
                case _:
                    logging.error(f'Unknown message type: {row}')

        # Insert metadata for this dump.
        dump_time = self.df['capture_ts'].max()
        c.execute("""
            INSERT INTO metadata (dump_time, deleted_vrps, unchanged_vrps, new_vrps)
            VALUES (%s, %s, %s, %s)
            """, (dump_time, num_deleted_vrps, num_unchanged_vrps, num_new_vrps))
        self.insert_or_update_latest_dump_ts(c, dump_time)

        # Set upper bound of visible range for deleted VRPs.
        logging.info(f'Setting upper bound of visible range for {len(update_rows)} VRPs')
        c.executemany("""
            UPDATE vrps
            SET visible = %s
            WHERE id = %s
        """, update_rows)

        # Insert new VRPs with visible range entirely within dump.
        logging.info(f'Inserting {len(insert_rows)} fluttered VRPs')
        c.executemany("""
            INSERT INTO vrps (prefix, asn, max_length, visible)
            VALUES (%s, %s, %s, %s)
        """, insert_rows)

        # Insert new VRPs.
        insert_data = [
            (vrp.prefix, vrp.asn, vrp.max_length, visible_range)
            for vrp, visible_range in insert_vrps.items()
        ]
        logging.info(f'Inserting {len(insert_data)} new VRPs')
        c.executemany("""
            INSERT INTO vrps (prefix, asn, max_length, visible)
            VALUES (%s, %s, %s, %s)
        """, insert_data)


if __name__ == '__main__':
    handlers = [
        logging.StreamHandler(sys.stdout)
    ]
    if os.path.exists('/log'):
        handlers.append(logging.FileHandler('/log/rpki-history.log'))
    FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(
        format=FORMAT,
        level=logging.INFO,
        handlers=handlers,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(f'Started: {sys.argv}')
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'update'])
    parser.add_argument('-t', '--timestamp', help='fetch file for specific timestamp (YYYYMMDDThhmmss)')
    parser.add_argument('-m', '--mode',
                        choices=['rpkiviews', 'ripencc', 'rpkiflutter'],
                        default='rpkiviews',
                        help='data source')
    args = parser.parse_args()
    mode = args.mode
    if mode == 'rpkiviews':
        rpki = RPKIViews()
    elif mode == 'ripencc':
        rpki = RIPENCCDaily()
    else:
        rpki = RPKIFlutter()
    command = args.command
    match command:
        case 'init':
            with rpki:
                rpki.init_db()
        case 'update':
            timestamp = None
            if args.timestamp:
                try:
                    timestamp = datetime.strptime(args.timestamp, '%Y%m%dT%H%M%S').replace(tzinfo=timezone.utc)
                except ValueError as e:
                    logging.error(f'Invalid timestamp specified: {args.timestamp} ({e})')
                    sys.exit(1)
            with rpki:
                rpki.update_db(timestamp)
    logging.info('Done')
    sys.exit(0)
