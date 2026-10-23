CREATE OR REPLACE TABLE brand_targets AS
SELECT date_trunc('month', event_ts)::DATE AS month, brand, count(*) AS n_urls,
       count(DISTINCT host) AS n_hosts,
       rank() OVER (PARTITION BY date_trunc('month', event_ts) ORDER BY count(*) DESC) AS rank_in_month
FROM stg_malicious_urls
WHERE brand IS NOT NULL
GROUP BY date_trunc('month', event_ts), brand
ORDER BY month DESC, n_urls DESC;
