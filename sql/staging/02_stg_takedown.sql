-- One row per URLhaus URL with a right-censored lifetime for survival analysis.
--   offline -> event observed, lifetime = last_online - date_added
--   online  -> censored,       lifetime = newest snapshot - date_added
CREATE OR REPLACE TABLE stg_takedown AS
WITH latest AS (
    SELECT *, row_number() OVER (PARTITION BY url ORDER BY snapshot_date DESC) AS rn
    FROM raw_urlhaus
), clock AS (SELECT max(snapshot_date)::TIMESTAMP + INTERVAL 1 DAY AS now_ts FROM raw_urlhaus)
SELECT
    l.url,
    regexp_extract(l.url, '^https?://(?:[^@/]*@)?([^/:?#]+)', 1) AS host,
    l.threat,
    l.date_added,
    (l.url_status = 'offline')::INTEGER AS taken_down,
    greatest(
        epoch(CASE WHEN l.url_status = 'offline' THEN coalesce(l.last_online, l.date_added)
                   ELSE c.now_ts END - l.date_added) / 3600.0,
        0.0) AS lifetime_hours
FROM latest l, clock c
WHERE l.rn = 1 AND l.date_added IS NOT NULL;
