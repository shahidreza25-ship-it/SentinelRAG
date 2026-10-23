import os
import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def retrieve_ioc(indicator):

    api_key = os.environ.get("ABUSEIPDB_API_KEY")

    if not api_key:
        raise RuntimeError(
            "ABUSEIPDB_API_KEY is not configured."
        )

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90
    }

    response = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=15
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"AbuseIPDB API error: {response.status_code}"
        )

    result = response.json()
    data = result.get("data", {})

    abuse_score = int(
        data.get("abuseConfidenceScore", 0)
    )

    total_reports = int(
        data.get("totalReports", 0)
    )

    country = data.get(
        "countryCode",
        "Unknown"
    )

    isp = data.get(
        "isp",
        "Unknown"
    )

    usage_type = data.get(
        "usageType",
        "Unknown"
    )

    if abuse_score >= 75:
        severity = "HIGH"
    elif abuse_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "indicator": indicator,
        "severity": severity,
        "confidence": abuse_score,
        "description": (
            f"AbuseIPDB reported {total_reports} "
            f"reports for this IP."
        ),
        "mitre": [],
        "total_reports": total_reports,
        "country": country,
        "isp": isp,
        "usage_type": usage_type,
        "source": "AbuseIPDB"
    }