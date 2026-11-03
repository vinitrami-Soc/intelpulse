"""The console, served by the app itself: the pages and the API on one origin (spec 4).

One origin means the console needs no CORS grant and no token in browser
storage: it signs in with the session cookie and calls `/api` on its own host.
The GitHub Pages copy of `web/` stays a static demo.

Only what a browser needs is served: the pages at the top of `web/` and
`web/assets/`. The browser test suites and `nginx.conf` live in the same
folder and are not served.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from xml.sax.saxutils import escape

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from .config import settings

# The documents anyone may read, and a search engine index when the owner allows it (spec 9.5).
PUBLIC_PAGES = ("product.html", "privacy.html", "help.html", "about.html", "terms.html")


def servable(path: str) -> bool:
    """`path` as StaticFiles hands it over: relative and already normalised."""
    parts = PurePosixPath(path).parts
    if not parts or parts == (".",):
        return True  # the folder itself: index.html
    if len(parts) == 1:
        return parts[0].endswith(".html")
    return parts[0] == "assets"


class ConsoleFiles(StaticFiles):
    async def get_response(self, path: str, scope: Scope) -> Response:
        if not servable(path):
            raise HTTPException(status_code=404)
        response = await super().get_response(path, scope)
        # Revalidated on every load (cheap, with the ETag): a redeploy is never half seen.
        response.headers.setdefault("Cache-Control", "no-cache")
        return response


def _base(request: Request) -> str:
    """PUBLIC_URL when set: the Host header is the caller's to choose, and a sitemap should not be."""
    return (settings.public_url.strip() or str(request.base_url)).rstrip("/")


def robots(request: Request) -> Response:
    if not settings.index_public_pages:
        body = "User-agent: *\nDisallow: /\n"
    else:
        allowed = "".join(f"Allow: /{page}\n" for page in PUBLIC_PAGES)
        body = f"User-agent: *\n{allowed}Disallow: /\nSitemap: {_base(request)}/sitemap.xml\n"
    return Response(body, media_type="text/plain; charset=utf-8", headers={"Cache-Control": "no-cache"})


def sitemap(request: Request) -> Response:
    if not settings.index_public_pages:
        raise HTTPException(status_code=404)
    base = _base(request)
    urls = "".join(f"  <url><loc>{escape(base)}/{page}</loc></url>\n" for page in PUBLIC_PAGES)
    body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + urls + "</urlset>\n")
    return Response(body, media_type="application/xml", headers={"Cache-Control": "no-cache"})
