"""Streamlit analyst dashboard.  Run: streamlit run dashboard/app.py"""
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from abuselens import config, db
from abuselens.analytics import survival

st.set_page_config(page_title="AbuseLens", layout="wide")
st.title("AbuseLens — URL abuse analytics")

con = db.connect()
for sub in ("staging", "marts"):
    db.run_sql_dir(con, sub)

trends = con.execute("SELECT * FROM daily_abuse_trends").df()
if trends.empty:
    st.warning("Warehouse is empty. Run `abuselens ingest --sources urlhaus openphish tranco` first.")
    st.stop()

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Trends", "Brands & infrastructure", "Campaigns",
                                        "Takedown speed", "Model health"])
with tab1:
    daily = trends.groupby(["day", "abuse_type"], as_index=False).n_urls.sum()
    st.plotly_chart(px.area(daily, x="day", y="n_urls", color="abuse_type",
                            title="New malicious URLs per day"), use_container_width=True)
    st.caption("Spikes are usually one platform or campaign flooding the feed; check the host table in "
               "the next tab.")

with tab2:
    c1, c2 = st.columns(2)
    brands = con.execute("SELECT brand, sum(n_urls) n FROM brand_targets GROUP BY 1 ORDER BY 2 DESC LIMIT 15").df()
    if brands.empty:
        c1.info("No brand labels yet. Brand names come from PhishTank, which is not connected.")
    else:
        c1.plotly_chart(px.bar(brands, x="n", y="brand", orientation="h", title="Most impersonated brands"),
                        use_container_width=True)
    hosts = con.execute("SELECT host, n_urls FROM host_abuse ORDER BY n_urls DESC LIMIT 15").df()
    c2.plotly_chart(px.bar(hosts.iloc[::-1], x="n_urls", y="host", orientation="h",
                           title="Most abused hosts (malicious URLs)"), use_container_width=True)
    st.caption("Large shares on github.com, Google Drive, Discord or Dropbox mean attackers are "
               "abusing trusted file hosts, not just registering their own domains.")
    tlds = con.execute("SELECT tld, sum(n_urls) n FROM tld_abuse GROUP BY 1 ORDER BY 2 DESC LIMIT 15").df()
    st.plotly_chart(px.bar(tlds, x="n", y="tld", orientation="h", log_x=True,
                           title="Most abused TLDs (log scale; .com is inflated by GitHub-hosted URLs)"),
                    use_container_width=True)
    st.subheader("Hosting networks / registrars")
    hosting = con.execute("SELECT * FROM hosting_abuse LIMIT 25").df()
    if hosting.empty:
        st.info("No hosting data yet. Run `abuselens enrich --max 300` to add registrar and ASN context.")
    else:
        st.dataframe(hosting)

with tab3:
    st.dataframe(con.execute("SELECT * FROM campaigns LIMIT 100").df())

with tab4:
    td = survival.load(con)
    if len(td) > 30:
        overall = survival.kaplan_meier(td).iloc[0]
        c1, c2 = st.columns(2)
        c1.metric("Median lifetime (hours)", f"{overall.median_hours:.0f}")
        c2.metric("Still live after 7 days", f"{overall.survival_7d:.0%}")
        km = survival.kaplan_meier(td, "host")
        km["median_hours"] = km["median_hours"].map(
            lambda v: "not reached" if pd.isna(v) or v == float("inf") else round(v, 1))
        st.caption("'not reached' = fewer than half of that host's URLs were taken down during the window.")
        st.dataframe(km)
        st.subheader("Cox hazard ratios (HR<1 = slower takedown)")
        st.dataframe(survival.cox_by_host(td))
    else:
        st.info("Not enough takedown data yet.")

with tab5:
    p = config.MODEL_DIR / "champion" / "meta.json"
    if p.exists():
        meta = json.loads(p.read_text(encoding="utf-8"))
        m = meta["metrics"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("PR-AUC", f"{m['pr_auc']:.3f}")
        c2.metric("Recall at threshold", f"{m['recall']:.1%}")
        c3.metric("Safe wrongly flagged", f"{m['fpr']:.2%}")
        c4.metric("Precision at 1% prevalence", f"{m['precision_at_prevalence']:.0%}")
        st.write(f"Trained {meta['trained_at'][:16]} on {meta['train_range'][0][:10]} to "
                 f"{meta['train_range'][1][:10]}; tested on {meta['test_range'][0][:10]} to "
                 f"{meta['test_range'][1][:10]}. Decision: **{meta['decision']}**.")
        champ = meta.get("champion_metrics_on_same_holdout")
        if champ:
            st.subheader("Challenger vs previous champion (same held-out data)")
            keys = ("pr_auc", "roc_auc", "recall", "fpr", "precision_at_prevalence")
            st.dataframe(pd.DataFrame({
                "challenger": {k: m[k] for k in keys},
                "previous champion": {k: champ[k] for k in keys},
            }).round(4))
        with st.expander("Raw model metadata"):
            st.json(meta)
    else:
        st.info("No model trained yet. Run `abuselens train`.")
