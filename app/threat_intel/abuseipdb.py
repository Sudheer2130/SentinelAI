import httpx
from typing import Optional, Dict, Any
from ..config import settings
from .cache import threat_cache
from ..models.schemas import IOCItem, IOCType

# Offline / Mock Intelligence dataset for known test / cyber range IPs
KNOWN_IP_DB = {
    "185.220.101.5": {
        "score": 98,
        "is_malicious": True,
        "country": "DE",
        "isp": "Tor Exit Node Network",
        "tags": ["Tor Exit Node", "Cobalt Strike C2", "Scanner"],
        "reports": 3412
    },
    "194.26.29.112": {
        "score": 95,
        "is_malicious": True,
        "country": "RU",
        "isp": "Bulletproof Hosting AS202425",
        "tags": ["Cobalt Strike Malleable C2", "Malware Hosting"],
        "reports": 1824
    },
    "45.154.255.89": {
        "score": 90,
        "is_malicious": True,
        "country": "NL",
        "isp": "HostPalace Web Solutions",
        "tags": ["Port Scanner", "RDP Brute Force"],
        "reports": 890
    },
    "8.8.8.8": {
        "score": 0,
        "is_malicious": False,
        "country": "US",
        "isp": "Google LLC",
        "tags": ["Anycast DNS", "Benign"],
        "reports": 0
    },
    "1.1.1.1": {
        "score": 0,
        "is_malicious": False,
        "country": "US",
        "isp": "Cloudflare Inc",
        "tags": ["DNS Resolver", "Benign"],
        "reports": 0
    }
}

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> IOCItem:
        cache_key = f"abuseipdb:{ip_address}"
        cached = threat_cache.get(cache_key)
        if cached:
            return IOCItem(**cached)

        # Check internal knowledge base first if offline / no key
        if not self.api_key:
            return self._fallback_intel(ip_address)

        # Live API query
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                headers = {
                    "Accept": "application/json",
                    "Key": self.api_key
                }
                params = {
                    "ipAddress": ip_address,
                    "maxAgeInDays": max_age_in_days,
                    "verbose": True
                }
                response = await client.get(f"{self.base_url}/check", headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    is_mal = score >= 50
                    tags = []
                    if score > 75:
                        tags.append("High Abuse Threat")
                    if data.get("isTor"):
                        tags.append("Tor Node")
                    if data.get("usageType"):
                        tags.append(data.get("usageType"))

                    item = IOCItem(
                        ioc_type=IOCType.IP,
                        value=ip_address,
                        source_context="AbuseIPDB v2",
                        reputation_score=score,
                        is_malicious=is_mal,
                        provider="AbuseIPDB Live API",
                        tags=tags,
                        details={
                            "country": data.get("countryCode"),
                            "isp": data.get("isp"),
                            "domain": data.get("domain"),
                            "totalReports": data.get("totalReports")
                        }
                    )
                    threat_cache.set(cache_key, item.model_dump())
                    return item
                else:
                    return self._fallback_intel(ip_address)
        except Exception:
            return self._fallback_intel(ip_address)

    def _fallback_intel(self, ip_address: str) -> IOCItem:
        if ip_address in KNOWN_IP_DB:
            k = KNOWN_IP_DB[ip_address]
            return IOCItem(
                ioc_type=IOCType.IP,
                value=ip_address,
                source_context="Known Threat Intel DB",
                reputation_score=k["score"],
                is_malicious=k["is_malicious"],
                provider="Threat Intelligence Feed (Offline)",
                tags=k["tags"],
                details={
                    "country": k["country"],
                    "isp": k["isp"],
                    "reports": k["reports"]
                }
            )

        # Private IP heuristics
        if ip_address.startswith(("10.", "192.168.", "172.16.", "127.")):
            return IOCItem(
                ioc_type=IOCType.IP,
                value=ip_address,
                source_context="RFC1918 Private Network",
                reputation_score=0,
                is_malicious=False,
                provider="Internal Subnet Classifier",
                tags=["Internal Subnet", "Private IP"],
                details={"scope": "RFC1918"}
            )

        # Default unknown external IP
        return IOCItem(
            ioc_type=IOCType.IP,
            value=ip_address,
            source_context="Global External IP",
            reputation_score=35,
            is_malicious=False,
            provider="Heuristic Baseline",
            tags=["External Public IP", "Uncategorized"],
            details={"status": "No prior abuse history logged"}
        )

abuse_client = AbuseIPDBClient()
