-- Unified, de-duplicated malicious URLs from all feeds. Earliest sighting wins.
CREATE OR REPLACE TABLE stg_malicious_urls AS
WITH unioned AS (
    SELECT url, 'urlhaus' AS source,
           CASE WHEN lower(threat) LIKE '%malware%' THEN 'malware_download' ELSE coalesce(lower(threat), 'malware_download') END AS abuse_type,
           NULL::VARCHAR AS brand,
           date_added AS event_ts
    FROM raw_urlhaus
    UNION ALL
    SELECT url, 'openphish', 'phishing', NULL, snapshot_date::TIMESTAMP FROM raw_openphish
    UNION ALL
    SELECT url, 'phishtank', 'phishing',
           CASE WHEN target IS NULL OR lower(target) IN ('other', 'n/a', '') THEN NULL ELSE target END,
           submission_time
    FROM raw_phishtank
), ranked AS (
    SELECT *, row_number() OVER (PARTITION BY url ORDER BY event_ts NULLS LAST) AS rn,
           max(brand) OVER (PARTITION BY url) AS brand_any
    FROM unioned
)
SELECT url, source, abuse_type, brand_any AS brand, event_ts,
       regexp_extract(url, '^https?://(?:[^@/]*@)?([^/:?#]+)', 1) AS host
FROM ranked
WHERE rn = 1 AND event_ts IS NOT NULL;

CREATE OR REPLACE TABLE stg_safe_urls AS
SELECT DISTINCT ON (url) url, source, domain AS host, tranco_rank, snapshot_date::TIMESTAMP AS event_ts
FROM raw_safe_urls
ORDER BY url, snapshot_date;
