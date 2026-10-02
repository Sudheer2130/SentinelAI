import time
from typing import Dict, Any, Optional

class ThreatIntelCache:
    def __init__(self, default_ttl: int = 86400):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() < entry["expires_at"]:
                return entry["data"]
            else:
                del self._cache[key]
        return None

    def set(self, key: str, data: Any, ttl: Optional[int] = None) -> None:
        expiry = time.time() + (ttl if ttl is not None else self.default_ttl)
        self._cache[key] = {
            "data": data,
            "expires_at": expiry
        }

    def clear(self) -> None:
        self._cache.clear()

threat_cache = ThreatIntelCache()
