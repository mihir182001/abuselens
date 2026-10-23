-- Most-abused TLDs, hosts, and (when enrichment has run) registrars / hosting networks.
CREATE OR REPLACE TABLE tld_abuse AS
SELECT regexp_extract(host, '\.([a-z0-9-]+)$', 1) AS tld, abuse_type,
       count(*) AS n_urls, count(DISTINCT host) AS n_hosts
FROM stg_malicious_urls
WHERE host NOT SIMILAR TO '[0-9.]+' AND host <> ''
GROUP BY ALL
ORDER BY n_urls DESC;

CREATE OR REPLACE TABLE host_abuse AS
SELECT host, count(*) AS n_urls, min(event_ts) AS first_seen, max(event_ts) AS last_seen,
       list_sort(list(DISTINCT abuse_type)) AS abuse_types
FROM stg_malicious_urls
WHERE host <> ''
GROUP BY host
ORDER BY n_urls DESC;

CREATE OR REPLACE TABLE hosting_abuse AS
WITH e AS (
    SELECT DISTINCT ON (domain) * FROM raw_enrichment ORDER BY domain, enriched_at DESC
)
SELECT e.asn, e.asn_org, e.registrar, count(*) AS n_urls, count(DISTINCT m.host) AS n_hosts
FROM stg_malicious_urls m
JOIN e ON e.domain = m.host
GROUP BY ALL
ORDER BY n_urls DESC;
