def collect_ioc(ioc_type, value):
    return {
        "type": ioc_type,
        "indicator": value.strip(),
        "status": "collected",
        "source": "SentinelRAG Collector Agent"
    }