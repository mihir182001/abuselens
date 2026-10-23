# Data dictionary

## Raw tables (one snapshot per `snapshot_date`)
| Table | Columns |
|---|---|
| raw_urlhaus | url, date_added, url_status, last_online, threat, tags, reporter, snapshot_date |
| raw_openphish | url, snapshot_date |
| raw_phishtank | url, phish_id, submission_time, verified, online, target, snapshot_date |
| raw_safe_urls | url, domain, tranco_rank, source (commoncrawl/tranco), snapshot_date |
| raw_enrichment | domain, domain_age_days, registrar, asn, asn_org, cert_count, enriched_at |
| ingest_log | run_ts, source, snapshot_date, rows_loaded, status (ok/rejected/error), message |

## Staging
- `stg_malicious_urls` — deduplicated across feeds (earliest sighting wins); `event_ts` = first-seen time.
- `stg_safe_urls` — deduplicated safe URLs with Tranco rank.
- `stg_takedown` — one row per URLhaus URL: `taken_down` (1 = offline, observed) / 0 (censored),
  `lifetime_hours`.

## Marts
- `daily_abuse_trends(day, abuse_type, source, n_urls, n_hosts)`
- `brand_targets(month, brand, n_urls, n_hosts, rank_in_month)`
- `tld_abuse`, `host_abuse`, `hosting_abuse` (needs enrichment)
- `campaigns(campaign_id, host, path_shape, n_urls, first_seen, last_seen, active_days)` — ≥5 URLs on one host
  with the same normalised path template
- `takedown_times(host, n_urls, n_taken_down, takedown_rate, median_lifetime_hours)`
