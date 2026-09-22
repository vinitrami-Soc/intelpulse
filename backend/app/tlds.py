"""Which last labels are actually top-level domains.

Why a list at all
-----------------
`is_plausible_domain` used to accept any dotted string whose final label was not
on a denylist of file extensions. A denylist of things that are *not* TLDs can
never be complete, and the multi-format corpus proved it: `j.doe` and `k.patel`
were queried as domains (318 times across 3,400 lines), along with `x.php`,
`index.html`, `core.dmp` and `web.config`. Sending an employee's username to a
threat-intel vendor is worse than the wasted quota.

The set of things that *are* TLDs is finite and published, so this file holds it.

How the check works
-------------------
Two rules, in this order:

1. **Every two-letter label is accepted.** All ccTLDs are ISO 3166-1 alpha-2
   codes, so this covers `.in`, `.uk`, `.ru`, `.io`, `.co` and the rest without
   enumerating them — and the cost of the rule is that a two-letter filename
   extension would pass, which is why `GENERIC` below still lists the handful
   that matter.
2. **Longer labels must be in `GENERIC`.** That is the original gTLDs, the
   sponsored ones, and the new-gTLD delegations that actually turn up in threat
   intelligence and in normal traffic.

Keeping it current
------------------
The set below is a snapshot, not a live feed. IANA publishes the authoritative
list at https://data.iana.org/TLD/tlds-alpha-by-domain.txt; refresh with:

    python -m app.cli refresh-tlds

That writes `data/tlds.txt`, which this module prefers over the snapshot when it
is present. The snapshot stays in the source so a fresh checkout with no network
still rejects `j.doe`, and so the refresh is an upgrade rather than a
prerequisite.

A TLD delegated after the snapshot and never refreshed is rejected, and that
shows up as a recall drop in `test_extraction_corpus.py` rather than silently.
The trade is deliberate: a missed new-gTLD domain is a visible, measured gap; a
username shipped to a threat-intel vendor is neither.
"""
from __future__ import annotations

from pathlib import Path

# Original and early generic TLDs.
_ORIGINAL = {
    "com", "org", "net", "edu", "gov", "mil", "int", "arpa",
    "biz", "info", "name", "pro", "aero", "coop", "museum",
    "asia", "cat", "jobs", "mobi", "tel", "travel", "post", "xxx",
}

# New-gTLD delegations. Not the full IANA list — the ones that carry real
# traffic, plus the ones that show up in threat reporting far out of proportion
# to their size (top, xyz, click, link, live, online, site, club, icu, cfd).
_NEW = {
    "academy", "accountant", "agency", "ai", "app", "art", "auto", "band",
    "bar", "bargains", "beauty", "best", "bid", "bike", "bio", "blog", "blue",
    "boutique", "build", "builders", "business", "buzz", "cab", "cafe", "camera",
    "camp", "capital", "cards", "care", "careers", "cash", "casino", "catering",
    "center", "ceo", "cfd", "chat", "cheap", "church", "city", "claims", "cleaning",
    "click", "clinic", "clothing", "cloud", "club", "coach", "codes", "coffee",
    "college", "community", "company", "computer", "condos", "construction",
    "consulting", "contractors", "cooking", "cool", "country", "coupons",
    "courses", "credit", "cricket", "cruises", "dance", "date", "dating", "deals",
    "degree", "delivery", "democrat", "dental", "dentist", "design", "dev",
    "diamonds", "diet", "digital", "direct", "directory", "discount", "doctor",
    "dog", "domains", "download", "earth", "education", "email", "energy",
    "engineer", "engineering", "enterprises", "equipment", "estate", "events",
    "exchange", "expert", "exposed", "express", "fail", "faith", "family", "fans",
    "farm", "fashion", "finance", "financial", "fish", "fishing", "fit", "fitness",
    "flights", "florist", "flowers", "football", "forsale", "foundation", "fun",
    "fund", "furniture", "futbol", "fyi", "gallery", "game", "games", "garden",
    "gift", "gifts", "gives", "glass", "global", "gold", "golf", "graphics",
    "gratis", "green", "gripe", "group", "guide", "guitars", "guru", "haus",
    "health", "healthcare", "help", "hiphop", "hockey", "holdings", "holiday",
    "homes", "horse", "host", "hosting", "house", "how", "icu", "immo", "inc",
    "industries", "ink", "institute", "insure", "international", "investments",
    "irish", "jetzt", "jewelry", "kaufen", "kim", "kitchen", "kiwi", "land",
    "lawyer", "lease", "legal", "lgbt", "life", "lighting", "limited", "limo",
    "link", "live", "loan", "loans", "lol", "london", "love", "ltd", "luxury",
    "maison", "management", "market", "marketing", "markets", "mba", "media",
    "memorial", "men", "menu", "moda", "moe", "money", "monster", "mortgage",
    "moscow", "movie", "nagoya", "network", "news", "ninja", "nyc", "one", "onl",
    "online", "ooo", "page", "paris", "partners", "parts", "party", "pet",
    "photo", "photography", "photos", "physio", "pics", "pictures", "pink",
    "pizza", "place", "plumbing", "plus", "poker", "porn", "press", "productions",
    "properties", "property", "pub", "quest", "racing", "realty", "recipes",
    "red", "rehab", "reise", "reisen", "rent", "rentals", "repair", "report",
    "republican", "rest", "restaurant", "review", "reviews", "rich", "rip",
    "rocks", "rodeo", "run", "sale", "salon", "sarl", "school", "schule",
    "science", "seat", "security", "services", "sexy", "shiksha", "shoes", "shop",
    "shopping", "show", "singles", "site", "ski", "soccer", "social", "software",
    "solar", "solutions", "space", "sport", "store", "stream", "studio", "study",
    "style", "supplies", "supply", "support", "surf", "surgery", "systems",
    "tattoo", "tax", "taxi", "team", "tech", "technology", "tennis", "theater",
    "tienda", "tips", "tires", "today", "tokyo", "tools", "top", "tours", "town",
    "toys", "trade", "trading", "training", "tube", "university", "uno", "vacations",
    "vegas", "ventures", "vet", "viajes", "video", "villas", "vin", "vip",
    "vision", "vodka", "voyage", "watch", "webcam", "website", "wedding", "wiki",
    "win", "wine", "work", "works", "world", "wtf", "xyz", "yoga", "zone",
    # Delegated in 2023, and immediately abused for phishing *because* they
    # collide with file extensions. See `declared` in app/ioc.py for how the
    # collision is resolved.
    "zip", "mov",
}

# A few brand TLDs that resolve real hosts people actually visit.
_BRAND = {"google", "youtube", "amazon", "apple", "microsoft", "dev", "goog", "gle"}

#: The snapshot compiled into the source, used when no refresh has been run.
SNAPSHOT: frozenset[str] = frozenset(_ORIGINAL | _NEW | _BRAND)

#: Where `python -m app.cli refresh-tlds` writes the authoritative IANA list.
IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "tlds.txt"


def parse_iana(text: str) -> frozenset[str]:
    """The IANA file: one uppercase TLD per line, after a `#` comment header."""
    labels = {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    # A file that parses to a handful of entries is a captive portal or an error
    # page, not the TLD list. Overwriting a working allowlist with that would
    # silently drop every domain, so refuse it here rather than write it out.
    if len(labels) < 500:
        raise ValueError(f"expected >=500 TLDs from IANA, parsed {len(labels)}")
    return frozenset(labels)


def _load() -> frozenset[str]:
    try:
        cached = parse_iana(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return SNAPSHOT
    # Union, not replacement: the snapshot carries `.dev` and `.zip` style
    # entries the parser needs even if a refresh ever returns a partial list.
    return SNAPSHOT | cached


GENERIC: frozenset[str] = _load()


def is_tld(label: str) -> bool:
    """True when `label` can be the last label of a real hostname."""
    label = label.strip().lower()
    if not label or not label.isascii():
        # Internationalised TLDs arrive punycoded as xn--…, handled below.
        return False
    if label.startswith("xn--"):
        return len(label) > 4
    if not label.isalpha():
        return False
    # Every ccTLD is two letters, so the shape is the rule and no list is needed.
    if len(label) == 2:
        return True
    return label in GENERIC
