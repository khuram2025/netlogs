# Analytics history during appliance upgrades

Schema migrations create tables and materialized views without running a full
historical aggregation during web startup. The appliance updater stops all
writers before this step. Apply image changes through the appliance updater;
do not replace the web image alone while an older ingestion process is running.

For newly introduced analytics tables, migration setup captures hard-linked
ClickHouse source parts with retention and automatic merging disabled on the
private copies. Existing raw logs and their retention policy are unchanged.
The snapshots keep the history boundary stable through restarts. Once setup
finishes, materialized views collect new events, including late arrivals, in
the original analytics tables.

A single background worker reads up to 250,000 source rows per batch. It uses
one query thread, a 512 MiB query memory limit, a 90-second execution limit,
small insert blocks and disk-spill settings. Policy counts stream one hit per
event into AggregatingMergeTree; they do not require a full-history GROUP BY.
The threat projection uses the same field mappings as its live materialized
view. Historical processing includes the raw history available at migration
time, subject to each destination table's retention policy.

Each batch has a deterministic private history partition. The worker builds
its result in a staging table, atomically replaces that partition, and then
records progress. An interrupted or timed-out insertion remains hidden in
staging. A crash after publication but before the progress checkpoint safely
replaces the same partition on retry, instead of adding duplicate counts.
Live and historical records remain separate and are queried through union
views. A background failure never marks the unfinished history complete.

Progress appears in **System > Storage Monitor > Historical analytics
processing**. During catch-up, historical analytics are partial; Log Explorer
continues to expose the original logs. Errors retain a database error code and
retry with backoff. Snapshots are removed after completion. Snapshots share
disk files initially, but can retain older files as the live source merges or
expires; allow space for the derived analytics and normal ingestion.

Already initialized analytics on earlier releases are retained. This mechanism
does not infer or repair historical duplicates that an earlier release may
already have written. The normal cold backup and recovery process includes
the source snapshots, staging tables, history and progress ledger together.
