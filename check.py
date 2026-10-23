import duckdb
c = duckdb.connect("data/abuselens.duckdb", read_only=True)
print(c.execute("select source, count(*) n from stg_safe_urls group by 1").df())
print(c.execute("select abuse_type, source, count(*) n from stg_malicious_urls group by 1, 2").df())
print(c.execute("select url from stg_safe_urls where source = 'sitelinks' limit 8").df().to_string())
