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

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope


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
