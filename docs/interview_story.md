# AbuseLens: interview story

## 60-second pitch

"I built a pipeline that runs every day on GitHub Actions. It pulls real malicious URLs from URLhaus and
OpenPhish, samples safe URLs from lower-ranked Tranco sites using real internal links, validates each feed,
and loads daily snapshots into a DuckDB warehouse. SQL marts show trends, targeted hosts and TLDs, and attack
campaigns. A calibrated XGBoost model scores URLs at a fixed 1% false-positive budget, and monitoring checks
drift and accuracy over time. It also produces a weekly risk brief. The most useful findings were about the
data: about 40% of malware URLs are hosted on GitHub alone, and Google Drive, Discord and Dropbox appear in the top campaigns, and malware stays up
for a median of about 12 days."

## Decisions and why

| Decision | Why |
|---|---|
| Safe URLs from Tranco ranks 1,000 to 1,000,000, with real internal links as paths | Top-ranked domains are trivially safe, so a naive model learns "unpopular = malicious". Real paths stop it learning "no path = safe". |
| Metric is recall at a **fixed 1% false-positive rate** | Trust & Safety cares about how many legitimate users get hurt; a single accuracy number hides that. |
| Precision re-weighted to **1% prevalence** | The test set is mostly malicious, so raw precision and PR-AUC are inflated. 58.8% is what to expect in the real world. |
| Time-based split, per abuse type | Random splits leak near-duplicate URLs from the same campaign across train and test. |
| Strict host-disjoint evaluation | Checks the model is not just remembering hosts. |
| Isotonic calibration and a frozen threshold | Scores mean probabilities, and the operating point does not move silently. |
| Champion/challenger on the same hold-out | A retrain must beat the current model on the same data before it replaces it. |
| Right-censored survival analysis (Kaplan-Meier, Cox) | URLs still online are not "never taken down"; dropping them would bias takedown times downward. |
| Quality gates before load | A broken feed (schema change, empty file, volume collapse) is rejected and logged, not silently loaded. |
| Warehouse stored as a release asset | Actions caches expire; the history behind drift and decay must not. |

## Mistakes I found and fixed (be ready to tell these)

1. **Split bug.** One global time cut put all OpenPhish URLs (all stamped with the pull date) in the test set,
   so the model never saw phishing; phishing recall was 70%. Splitting per abuse type fixed it (89%).
2. **False drift alerts.** First drift check compared safe against malicious mixes and tiny phishing samples,
   so it fired constantly. Now it runs per abuse type with minimum rows and days.
3. **Overstated decay.** My first decay table scored training rows, which made recall look like it was falling
   (99.7% to 97.7%). Scoring only rows newer than each type's training data shows flat recall (98.2% to 98.5%).
   The lesson: a monitoring chart must only use data the model has not seen.
4. **Data source reality.** URLhaus moved to a keyed endpoint, PhishTank registration closed, and Common Crawl's
   index returned 504s. I replaced the safe-path source with real internal links from each sampled site.

## Findings to quote

- About 40% of malware URLs are on GitHub alone; Google Drive, Discord and Dropbox appear in the top campaigns.
  Domain blocking cannot handle that class; it needs path-level and reputation-per-account signals.
- Median malware URL lifetime is 301 hours; 52% still live after 7 days.
- Slowest takedown by host (Kaplan-Meier): github.com median about 695 hours; some raw-IP hosts never reach a
  median in the window.
- Campaigns: 100+ URLs on one IP or one Google Drive path share the same URL template across 29 to 31 days.
- Model: 98.1% recall at 0.69% false positives; 58.8% precision at 1% prevalence.

## Likely questions

**"Why is PR-AUC 0.998 and precision only 58.8%?"** PR-AUC depends on the class mix of the test set. Mine is
mostly malicious. At 1% real prevalence, even a 0.69% false-positive rate means roughly as many false alarms as
true detections, so precision is about 59%. That is why I report the re-weighted number.

**"Is the model really detecting phishing?"** Partly. Phishing recall is about 87 to 89% with ROC-AUC 0.985 and it
holds under a host-disjoint split, but the test set is only about 130 URLs from one feed, and top features are
malware-style signals. I would call it a strong malware-URL detector with useful phishing detection on top.

**"How do you know it is not just learning the data source?"** I can't fully rule it out. Malware and safe URLs
differ in how they were collected, so lexical shortcuts are possible. I checked feature importances, ran a
host-disjoint split, and sampled safe URLs with real paths. Next I would add content or reputation signals.

**"What would you do with more time?"** Brand labels for phishing (PhishTank is closed, so infer from URLs),
separate evaluation of "trusted platform" versus "dedicated host" malware, domain age and ASN enrichment (code is
written, not yet run), and a longer time-based phishing test as daily data accumulates.

**"How would this work at Google scale?"** The design transfers: idempotent partitioned ingests, quality gates,
a feature code path shared by training and serving, calibration, frozen thresholds, and drift/decay monitoring.
The storage, scoring and human-review loops would be much larger.

## Honest limitations

- Safe URLs are *assumed* benign (Tranco ranks), so some labels are noisy.
- Phishing is one feed and about 600 URLs so far; drift for phishing needs 7 or more days.
- No PhishTank brand labels, so the brand charts are empty.
- Enrichment (domain age, registrar, ASN) is written but not run, so it is not part of the model.
- URLhaus `last_online` is a proxy for takedown time.
