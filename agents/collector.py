import ipaddress


def collect_ioc(ioc_type, value):
    value = value.strip()

    if ioc_type.upper() == "IP":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Invalid IP address.")

    return {
        "type": ioc_type.upper(),
        "indicator": value,
        "status": "collected",
        "source": "SentinelRAG Collector Agent"
    }