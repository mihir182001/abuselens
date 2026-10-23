-- Campaign = a group of URLs on the same host sharing a normalised path "shape"
-- (digits -> #, long hex/base64-ish tokens -> X). Template-generated phishing kits and
-- malware droppers collapse into one campaign instead of thousands of unique URLs.
CREATE OR REPLACE TABLE campaigns AS
WITH shaped AS (
    SELECT host, abuse_type, brand, event_ts,
           regexp_replace(
               regexp_replace(regexp_extract(url, '^https?://[^/]+(/[^?#]*)', 1),
                              '[A-Za-z0-9]{16,}', 'X', 'g'),
               '[0-9]+', '#', 'g') AS path_shape
    FROM stg_malicious_urls
)
SELECT md5(host || '|' || path_shape) AS campaign_id, host, path_shape,
       min(abuse_type) AS abuse_type, max(brand) AS brand,
       count(*) AS n_urls, min(event_ts) AS first_seen, max(event_ts) AS last_seen,
       date_diff('day', min(event_ts), max(event_ts)) + 1 AS active_days
FROM shaped
WHERE host <> ''
GROUP BY host, path_shape
HAVING count(*) >= 5
ORDER BY n_urls DESC;
