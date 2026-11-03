/* IntelPulse · where the console's data comes from.
 *
 * The same files run in two places. Served by an IntelPulse server, the console
 * signs in and works on the workspace's own data (ServerSource). Opened from
 * GitHub Pages or from disk, it is the demo: synthetic data scored in the
 * browser (DemoSource), exactly as before.
 *
 * Which one is decided once, at load, by assets/mode.json. The file in web/
 * says {"mode": "demo"}, and a static host (GitHub Pages, nginx, http.server)
 * serves it as it is; an IntelPulse server answers that path itself with
 * {"mode": "server"}. So the demo never asks for anything that is not there
 * (no 404 in the console), and only a server is asked for GET /api/session.
 * No answer, a slow one or a file:// page is the demo.
 *
 * The session lives in an HttpOnly cookie the page cannot read. The CSRF token
 * the server hands out with it is kept in memory only, never in storage, and
 * rides on every write as X-CSRF-Token. Nothing here stores a credential.
 */
(function () {
  "use strict";

  const text = (value, limit) => (typeof value === "string" ? value.slice(0, limit || 200) : "");

  /* The session answer is input like any other: only known fields, each checked. */
  function cleanSession(body) {
    const user = body && body.user && typeof body.user === "object" ? body.user : null;
    const workspace = body && body.workspace && typeof body.workspace === "object" ? body.workspace : null;
    return {
      setupNeeded: body.setup_needed === true,
      signupOpen: body.signup === true,
      emailEnabled: body.email === true,
      user: user && text(user.username, 64) ? {
        username: text(user.username, 64),
        displayName: text(user.display_name, 120) || text(user.username, 64),
        role: user.role === "admin" ? "admin" : "analyst",
        owner: user.owner === true,
        mustChangePassword: user.must_change_password === true
      } : null,
      workspace: workspace ? { name: text(workspace.name, 120), kind: workspace.kind === "individual" ? "individual" : "organization" } : null,
      csrf: text(body.csrf, 200)
    };
  }

  class ApiError extends Error {
    constructor(status, code, detail) {
      super(detail || "the request failed");
      this.status = status;
      this.code = code || "";
    }
  }

  async function readError(response) {
    let code = "", detail = response.statusText || ("HTTP " + response.status);
    try {
      const body = await response.json();
      if (body && typeof body.detail === "string") detail = body.detail;
      if (body && typeof body.error === "string") code = body.error;
    } catch (_) { /* not JSON */ }
    return new ApiError(response.status, code, detail);
  }

  /* ─── the demo: nothing leaves the browser ─── */
  const DemoSource = {
    kind: "demo",
    session: null,
    async request() { throw new ApiError(0, "demo", "the demo has no server"); }
  };

  /* ─── a server: same origin, the session cookie, the CSRF token on writes ─── */
  const ServerSource = {
    kind: "server",
    session: null,

    async request(path, options) {
      const opts = options || {};
      if (typeof path !== "string" || !/^\/api\//.test(path)) throw new ApiError(0, "path", "not an API path");
      const method = (opts.method || "GET").toUpperCase();
      const headers = { Accept: "application/json" };
      const body = opts.body;
      if (typeof body === "string") headers["Content-Type"] = "application/json";
      if (method !== "GET" && this.session && this.session.csrf) headers["X-CSRF-Token"] = this.session.csrf;
      const response = await fetch(path, {
        method, headers, body, signal: opts.signal, credentials: "same-origin", cache: "no-store"
      });
      if (!response.ok) {
        const error = await readError(response);
        if (response.status === 401 && this.session && this.session.user) {
          this.session = Object.assign({}, this.session, { user: null, csrf: "" });
          dispatchEvent(new CustomEvent("intelpulse:signed-out"));
        }
        throw error;
      }
      if (response.status === 204) return null;
      const type = response.headers.get("content-type") || "";
      return type.includes("application/json") ? response.json() : response.text();
    },

    async refresh() {
      const body = await this.request("/api/session");
      this.session = cleanSession(body || {});
      return this.session;
    },

    async signIn(username, password) {
      const body = await this.request("/api/session", {
        method: "POST", body: JSON.stringify({ username, password })
      });
      this.session = cleanSession(body || {});
      return this.session;
    },

    async setUp(fields) {
      const body = await this.request("/api/setup", { method: "POST", body: JSON.stringify(fields) });
      this.session = cleanSession(body || {});
      return this.session;
    },

    async signUp(fields) {
      const body = await this.request("/api/signup", { method: "POST", body: JSON.stringify(fields) });
      this.session = cleanSession(body || {});
      return this.session;
    },

    /* An invitation: what it opens (the token travels in a body, never in a URL), then the account. */
    async checkInvite(token) {
      const body = await this.request("/api/join/check", { method: "POST", body: JSON.stringify({ token }) });
      const workspace = body && body.workspace && typeof body.workspace === "object" ? body.workspace : {};
      return { workspace: text(workspace.name, 120), role: body && body.role === "admin" ? "admin" : "analyst" };
    },

    async join(fields) {
      const body = await this.request("/api/join", { method: "POST", body: JSON.stringify(fields) });
      this.session = cleanSession(body || {});
      return this.session;
    },

    /* The email flows: each answer is the server's sentence, shown as text. */
    async forgot(login) {
      const body = await this.request("/api/password/forgot", { method: "POST", body: JSON.stringify({ login }) });
      return text(body && body.detail, 300);
    },

    async resetPassword(token, password) {
      await this.request("/api/password/reset", { method: "POST", body: JSON.stringify({ token, password }) });
      /* every session of the account has ended, this browser's too if it was that account's */
      this.session = Object.assign({}, this.session, { user: null, csrf: "" });
    },

    async confirmEmail(token) {
      const body = await this.request("/api/email/confirm", { method: "POST", body: JSON.stringify({ token }) });
      return text(body && body.email, 254);
    },

    async changePassword(current, next) {
      await this.request("/api/profile", {
        method: "PATCH", body: JSON.stringify({ current_password: current, new_password: next })
      });
      return this.refresh();
    },

    async signOut() {
      try { await this.request("/api/session", { method: "DELETE" }); }
      finally { this.session = Object.assign({}, this.session, { user: null, csrf: "" }); }
    }
  };

  let source = DemoSource;

  async function detect() {
    if (location.protocol !== "http:" && location.protocol !== "https:") return source;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const get = async (path) => {
        const response = await fetch(path, {
          credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" },
          signal: controller.signal
        });
        const type = response.headers.get("content-type") || "";
        return response.ok && type.includes("application/json") ? response.json() : null;
      };
      const mode = await get("assets/mode.json");
      if (!mode || mode.mode !== "server") return source;
      const body = await get("/api/session");
      if (!body || typeof body !== "object" || body.mode !== "server") return source;
      ServerSource.session = cleanSession(body);
      source = ServerSource;
    } catch (_) {
      /* a static host, no network or a slow answer: the demo */
    } finally {
      clearTimeout(timer);
    }
    return source;
  }

  window.IntelPulseData = {
    ApiError,
    ready: detect(),
    get source() { return source; },
    get server() { return source === ServerSource; },
    get session() { return source.session; },
    request: (path, options) => source.request(path, options)
  };
})();
