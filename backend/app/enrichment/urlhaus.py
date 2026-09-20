"""abuse.ch URLhaus — malware distribution URLs, hosts and payload hashes."""
from __future__ import annotations

import httpx

from ..config import settings
from ..ioc import Indicator, url_host
from .base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Relation, Signal

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
PAYLOAD_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payload/"


class URLhausProvider(Provider):
    name = "urlhaus"
    label = "URLhaus (abuse.ch)"
    supported_types = {"ip", "domain", "url", "hash"}
    requires_key = False
    reference_url = "https://urlhaus.abuse.ch/browse.php?search={ioc}"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if settings.abusech_auth_key:
            headers["Auth-Key"] = settings.abusech_auth_key
        return headers

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        if indicator.type == "url":
            response = await client.post(
                URL_ENDPOINT, data={"url": indicator.value}, headers=self._headers()
            )
        elif indicator.type == "hash":
            field = {32: "md5_hash", 64: "sha256_hash"}.get(len(indicator.value))
            if not field:
                return self._result(indicator, facts={}, error="URLhaus indexes MD5/SHA256 only")
            response = await client.post(
                PAYLOAD_ENDPOINT, data={field: indicator.value}, headers=self._headers()
            )
        else:
            response = await client.post(
                HOST_ENDPOINT, data={"host": indicator.value}, headers=self._headers()
            )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") not in ("ok",):
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"urlhaus_status": data.get("query_status")},
                signals=[Signal("urlhaus", 0.0, "not listed on URLhaus")],
            )

        online = False
        families: list[str] = []
        tags: list[str] = []
        relations: list[Relation] = []
        facts: dict = {}

        if indicator.type == "url":
            online = data.get("url_status") == "online"
            facts = {
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "date_added": data.get("date_added"),
                "reporter": data.get("reporter"),
            }
            tags = [str(t) for t in (data.get("tags") or [])][:8]
            for payload in (data.get("payloads") or [])[:5]:
                family = payload.get("signature")
                if family and family not in families:
                    families.append(str(family))
                if payload.get("response_sha256"):
                    relations.append(
                        Relation(str(payload["response_sha256"]), "hash", "drops_payload", 0.85)
                    )
            host = url_host(indicator.value)
            if host:
                relations.append(Relation(host, "domain", "hosted_on", 0.8))
        elif indicator.type == "hash":
            facts = {
                "file_type": data.get("file_type"),
                "file_size": data.get("file_size"),
                "signature": data.get("signature"),
                "first_seen": data.get("firstseen"),
                "url_count": data.get("url_count"),
            }
            if data.get("signature"):
                families.append(str(data["signature"]))
            for url_entry in (data.get("urls") or [])[:5]:
                if url_entry.get("url"):
                    relations.append(Relation(str(url_entry["url"]), "url", "distributed_via", 0.8))
                online = online or url_entry.get("url_status") == "online"
        else:
            urls = data.get("urls") or []
            online = any(u.get("url_status") == "online" for u in urls)
            facts = {
                "url_count": int(data.get("url_count", len(urls)) or 0),
                "blacklists": data.get("blacklists"),
                "first_seen": data.get("firstseen"),
            }
            for url_entry in urls[:6]:
                if url_entry.get("url"):
                    relations.append(Relation(str(url_entry["url"]), "url", "hosts", 0.8))
                for tag in url_entry.get("tags") or []:
                    if tag not in tags:
                        tags.append(str(tag))

        value = 0.95 if online else 0.7
        relations += [Relation(f, "malware", "attributed_to", 0.85) for f in families]

        return self._result(
            indicator,
            status=STATUS_OK,
            facts=facts,
            tags=tags[:8],
            malware_families=families,
            attack_ids=["T1105"] if families or online else [],  # Ingress Tool Transfer
            relations=relations,
            signals=[
                Signal(
                    "urlhaus",
                    value,
                    "listed on URLhaus as "
                    + ("an ONLINE" if online else "a historic")
                    + " malware distribution point"
                    + (f" ({', '.join(families[:3])})" if families else ""),
                )
            ],
        )
