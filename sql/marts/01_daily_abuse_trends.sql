CREATE OR REPLACE TABLE daily_abuse_trends AS
SELECT event_ts::DATE AS day, abuse_type, source, count(*) AS n_urls,
       count(DISTINCT host) AS n_hosts
FROM stg_malicious_urls
GROUP BY ALL
ORDER BY day, abuse_type, source;
