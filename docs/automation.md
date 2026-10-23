# Running AbuseLens on a schedule (GitHub Actions)

* `ingest.yml` runs daily: downloads the warehouse (a file on the repo's `warehouse` release), pulls URLhaus,
  OpenPhish, Tranco and sitelinks, runs the quality gates, rebuilds the marts, and uploads the warehouse back.
* `retrain.yml` runs weekly: retrains, compares to the saved champion on the same hold-out, runs drift/decay
  monitoring, writes the risk brief and uploads the champion model and brief to the same release.
* `ci.yml` runs lint and tests on every push.

The warehouse lives in a release asset rather than the Actions cache because caches expire after 7 days of
non-use and would silently reset the history that drift and decay monitoring depend on.

## One-time setup
1. Create an empty GitHub repo and push this project (the `data/` folder is git-ignored).
2. Repo > Settings > Secrets and variables > Actions > New repository secret: `ABUSECH_AUTH_KEY`
   (optional: `PHISHTANK_API_KEY`).
3. Repo > Settings > Actions > General > Workflow permissions > "Read and write permissions".
4. Actions tab > `ingest` > Run workflow. The first run starts a fresh warehouse; later runs add a day each.
5. Seed with your local history (optional): `gh release create warehouse data/abuselens.duckdb --title warehouse`.
