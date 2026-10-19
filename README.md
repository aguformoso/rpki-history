# RPKI History

An API to query historical RPKI data, more specifically, Validated ROA Payloads
(VRPs).

Links:

* [GitHub](https://github.com/InternetHealthReport/rpki-history)
* [API](https://www.ihr.live/rpki-history/api/)

We obtain VRP data from the [RPKI Views](https://www.rpkiviews.org/) project and
store it in a compact form for fast access. In 2026 a new and improved
dataformat
([rpkispool](https://datatracker.ietf.org/doc/draft-snijders-rpkispool-format/))
based on [CCR
files](https://datatracker.ietf.org/doc/draft-ietf-sidrops-rpki-ccr/) was
introduced. Thus, the way we import data has changed over time.

#### Full Snapshots (until 2026)

From each dump we extract the `output/rpki-client.csv` file, which contains just
the VRPs, and update our database.

A VRP entry consists of five fields:

```csv
ASN,IP Prefix,Max Length,Trust Anchor,Expires
AS13335,1.0.0.0/24,24,apnic,1753280249
```

We ignore the expiry time and only work on dump-time granularity. For each
ingested dump we compare the set of VRPs (in form of `asn, prefix, max_length`)
with the previous dump. Each VRP has a `visible` time range, during which is was
continuously visible.  Since most VRPs are stable, this allows us to update just
the time range, keeping the database size compact.

#### rpkispool (from 2026)

Rpkispool files are created daily. Each file contains (amongst others) the CCR
files created by the different vantage points. Since the vantage points create
files at different frequencies, and can sometimes fail, we select the vantage
point that created the most CCR files for each day.

We process the CCR files sequentially ordered by creation time using
[rpki-client](https://www.rpki-client.org/) with `-f` and `-j` parameters.  We
extract the ROAPayloadState field that contains the VRPs. In CCR the
`max_length` field of a ROA can be absent, but for compatibility with the
previous format we set it to the prefix length in this case. The `visible` time
is handled the same.

Data limitations:

* **High-frequency updates are invisible.** With full snapshots dumps are
created roughly every 20 minutes, with rpkispool more frequent. However, if a
VRP expires / is removed and potentially recreated between dumps, this will not
be reflected in the database.

* **Data is at dump-time granularity.** If a VRP is created, expires, or is
* removed
between dumps, the exact point in time is lost. For example, if there are two
dumps at time `A` and `C`, a VRP expires at time `B` (`A < B < C`), and a user
queries for timestamp `D` (`A < D < B`) then the query will not find the VRP,
since its visibility ended at `A`. Similarly, VRPs that are only visible in one
dump will have equal values for the start and end visibility time.

* **Queryable time range is limited.** Naturally, we are limited by the amount
* of
available data. Trying queries outside of the available time range will result
in an error (to distinguish from non-existent VRPs).

Data sources:

* 2020-12-06 16:37:23 UTC to 2022-06-14 14:54:59 UTC:
[josephine.sobornost.net](https://josephine.sobornost.net/rpkidata/)
* 2022-06-14 15:08:09 UTC to 2025-12-31 23:53:28 UTC:
[dango.attn.jp](https://dango.attn.jp/rpkidata/)
* 2026-01-01 00:00:34 UTC to now: Move to rpkispool format. Each day the
vantage point with the most CCR files is selected. Please refer to the /status
endpoint for details about which vantage point was used for a specific time.

## Endpoints

### `/vrp`

Returns the list of covering VRPs for a prefix at a specific time, time range, or at the
latest dump time if no time parameter is specified.

#### Parameters

Mandatory:

* `prefix`: The prefix for which to return covering VRPs.

There are two types of time parameters, which are mutually exclusive: Point-in-time and
time range. For a time range only one bound can be specified, in which case the returned
list will include *all* earlier/later data available.

Point-in-time:

* `timestamp`: The timestamp (in `%Y-%m-%dT%H:%M:%S` [assumes UTC] or unix
epoch format) for which to return VRPs.

Time range:

* `timestamp__gte`: The start of the time range (inclusive; in
  `%Y-%m-%dT%H:%M:%S`[assumes UTC] or unix epoch format)
  for which to return VRPs.
* `timestamp__lte`: The end of the time range (inclusive; in `%Y-%m-%dT%H:%M:%S`
  [assumes UTC] or unix epoch format) for which to return VRPs.

#### Result Format

```json
// https://www.ihr.live/rpki-history/api/vrp?prefix=8.8.8.0/24
[
  {
    "prefix": "8.8.8.0/24",
    "asn": 15169,
    "max_length": 24,
    "visible": {
      "from": "2023-12-29T17:30:54+00:00",
      "to": "2025-08-13T06:29:10+00:00"
    }
  }
]
```

`visible` refers to the timespan during which the VRP was *continuously* visible, i.e.,
present in the dumps. Thus, if a VRP is missing from a dump, a new entry with a separate
`visible` range is created. **This time is unrelated to the validity time (`Not
before`/`Not after`) of the ROA!**

### `/status`

Returns the RPKI status for the specified prefix/ASN combination at the specified time,
or at the latest dump time if no timestamp is specified.

#### Parameters

Mandatory:

* `prefix`: The prefix to be checked.
* `asn`: The origin ASN of the prefix.

Optional:

* `timestamp`: The timestamp (in `%Y-%m-%dT%H:%M:%S` [assumes UTC] or unix epoch format)
for which to check the status. If omitted, use the latest available dump time.

#### Result Format

```json
// https://www.ihr.live/rpki-history/api/status?prefix=8.8.8.0/24&asn=15169
{
  "status": "Valid"
}

// https://www.ihr.live/rpki-history/api/status?prefix=8.8.8.0/25&asn=15169
{
  "status": "Invalid",
  "reason": {
    "code": "moreSpecific",
    "description": "Covering VRP with matching origin ASN found, but queried prefix is more specific than maxLength attribute allows."
  }
}
```

`status` is one of `[Valid, Invalid, NotFound]`.

`reason` (only for `Invalid` status) gives more detailed information about why the
status is invalid. `code` is for automatic processing, while `description` provides a
human-readable explanation.

### `/metadata`

Returns the list of dumps contained in the database. Since this list is very long, this
endpoint is paginated and returns at most 10000 results per page.

#### Parameters

Mandatory: None

Optional:

* `timestamp__gte`: The start of the time range (inclusive; in
  `%Y-%m-%dT%H:%M:%S`[assumes UTC] or unix epoch format)
  for which to return data.
* `timestamp__lte`: The end of the time range (inclusive; in `%Y-%m-%dT%H:%M:%S` [assumes UTC] or unix epoch format) for which to return data.
* `page`: The page number to load (defaults to 1).
* `page_size`: The number of results to include in one page (defaults to 10000).

#### Result Format

```json
// https://www.ihr.live/rpki-history/api/metadata
{
  "next": "https://www.ihr.live/rpki-history/api/metadata?page_size=1000&page=2",
  "results": [
    {
      "dump_timestamp": "2020-12-06T16:37:23+00:00",
      "ingest_timestamp": "2026-10-10T06:23:54+00:00",
      "deleted_vrps": 0,
      "unchanged_vrps": 0,
      "new_vrps": 205850,
      "vp": "josephine.sobornost.net",
      "vp_type": "full_snapshot"
    },
    // ...
  ]
}
```

`next` is the URL to the next page. It will be an empty string if there are no results
left.

`dump_timestamp` refers to the dump time (taken from the filename).

`ingest_timestamp` refers to the time this dump was imported.

`[deleted|updated|new]_vrps` indicates the number of VRPs differing from the previous
dump. Note that `deleted` refers to a VRP that was present in the previous dump, but not
in the current one.

`vp` is the RPKIviews vantage point that created the dump.

`vp_type` is the type of the vantage point. Historical dumps are based on full
snapshots, newer dumps use the rpkispool format.

## Database Dump

For easier analysis of the dataset, or self-hosting, [a dump of the database (updated
weekly) is available.](https://archive.ihr.live/ihr/rpki-history/)

## Self-hosting

If for some reason you want to host your own version of this page, here is how.

### Getting Started

Create secrets files containing the Postgres user passwords.

```bash
# For normal user
touch ./secrets/postgres-pw.txt
# For read-only user
touch ./secrets/postgres-ro-pw.txt
# Of course write actual passwords to these files...
```

Initialize database. This will also build the initial Docker image, which might take
some time.

```bash
docker compose run --rm init-db
```

**Optional:** Restore database dump.

```bash
docker compose exec -T database pg_restore -d rpki_history < rpki-history.dump
```

**Optional (but recommended):** Create an index over the prefix column to greatly
decrease query time. This is not built into the init-db script, since it is faster to
build the index once after all data was imported.

```bash
docker compose exec database psql -c "CREATE INDEX ON vrps USING gist (prefix inet_ops)"
```

Start the API server.

```bash
docker compose up -d api
```

### Updating the Data

To import the latest available data (uses RPKIViews by default):

```bash
docker compose run --rm update-db
```

For more usage options (e.g., importing a specific timestamp):

```bash
docker compose run --rm update-db --help
```

### Backup/restore Database

#### Backup

```bash
docker compose exec database pg_dump --data-only -Fc > rpki-history.dump
```

#### Restore

Assumes fresh install or that `postgres_data` volume was deleted.

```bash
# Reinitialize database to create schema *and additional user*.
docker compose run --rm init-db
# Restore data
docker compose exec -T database pg_restore -d rpki_history < rpki-history.dump
```
