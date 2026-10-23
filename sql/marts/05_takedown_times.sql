CREATE OR REPLACE TABLE takedown_times AS
SELECT host, count(*) AS n_urls, sum(taken_down) AS n_taken_down,
       round(avg(taken_down), 3) AS takedown_rate,
       round(median(lifetime_hours), 1) AS median_lifetime_hours
FROM stg_takedown
WHERE host <> ''
GROUP BY host
HAVING count(*) >= 5
ORDER BY median_lifetime_hours DESC;
