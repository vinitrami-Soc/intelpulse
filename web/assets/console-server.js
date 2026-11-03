/* IntelPulse · the console's views on a server's own data (spec 9.2).
 *
 * Signed in to an IntelPulse server, every view reads the workspace's own cases
 * from the API instead of the bundled sample: the overview's bands and trend,
 * the attack surface pushed alerts name, the triage history and queue, every
 * indicator, the attack narratives, the sources and the tickets. The demo keeps
 * its sample views (suite.js) and never loads anything from here.
 *
 * Each view is { title, sub, body(), mount(root, ctx) }, like the panes in
 * console-panes.js: body() is the frame, painted at once; mount() fetches and
 * fills it, and returns an unmount that aborts whatever is still in flight, so
 * a slow answer never lands in a view that has gone.
 *
 * Everything a server sends is input. Text is escaped where it is written, a
 * number is made a finite number before it is drawn, a link is scheme-checked,
 * and nothing is ever stored in the browser.
 */
(function () {
  "use strict";

  const U = (window.IntelPulsePanes && window.IntelPulsePanes.util) || null;
  const MODEL = window.IntelPulseConsole;
  if (!U || !MODEL) return;   // suite.js falls back to the sample views
  const { esc, safeUrl, badge, formatWhen } = U;

  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const $$ = (sel, scope) => Array.from((scope || document).querySelectorAll(sel));
  const finite = (value) => { const n = Number(value); return Number.isFinite(n) ? n : 0; };
  const whole = (value) => Math.max(0, Math.floor(finite(value)));
  const list = (value) => (Array.isArray(value) ? value : []);
  const objects = (value) => list(value).filter((item) => item && typeof item === "object");
  const text = (value) => (typeof value === "string" ? value : value == null ? "" : String(value));
  const count = (n, one, many) => whole(n).toLocaleString() + " " + (whole(n) === 1 ? one : many || one + "s");
  const when = (value) => (value ? formatWhen(value) : "never");

  const BANDS = ["critical", "high", "medium", "low", "informational"];
  const RANK = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const STATUS = { new: "Awaiting triage", in_progress: "In progress", closed: "Closed" };
  const REASONS = { true_positive: "true positive", false_positive: "false positive", benign: "benign", duplicate: "duplicate" };
  const statusText = (row) => (row.status === "closed" && REASONS[row.closed_reason]
    ? "Closed, " + REASONS[row.closed_reason] : STATUS[row.status] || "Awaiting triage");

  /* The session's request: same origin, the cookie, the CSRF token on writes. */
  const request = (path, options) => window.IntelPulseData.request(path, options);

  /* Seconds as a person says them: "45 s", "3 h 20 min", "2 d 4 h". */
  function duration(seconds) {
    const s = whole(seconds);
    if (s < 60) return s + " s";
    const m = Math.round(s / 60);
    if (m < 60) return m + " min";
    const h = Math.floor(m / 60);
    if (h < 48) return h + " h" + (m % 60 ? " " + (m % 60) + " min" : "");
    const d = Math.floor(h / 24);
    return d + " d" + (h % 24 ? " " + (h % 24) + " h" : "");
  }

  /* The same, to one unit, for a number that has to fit a card: "45 min", "15 h", "2 d". */
  function shortDuration(seconds) {
    const s = whole(seconds);
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + " min";
    if (s < 172800) return Math.round(s / 3600) + " h";
    return Math.round(s / 86400) + " d";
  }

  /* ─── shared pieces ─── */
  const loading = '<p class="wb-hint sv-loading" role="status">Loading…</p>';

  function emptyState(title, detail) {
    return '<div class="empty-state">' +
      '<svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8.5 13.5h7"/></svg>' +
      "<b>" + title + "</b><span>" + detail + "</span></div>";
  }
  const toWorkbench = 'Paste an alert in the <a class="wb-link" href="#/console/workbench">workbench</a> and its case lands here.';

  function failed(box, error, retry) {
    const detail = error && error.message ? error.message : "the server did not answer";
    box.innerHTML = '<div class="empty-state" role="alert">' +
      '<svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5v.5"/></svg>' +
      "<b>This view could not load</b><span>" + esc(detail) + "</span>" +
      '<button type="button" class="btn btn-light btn-sm" data-sv-retry>Try again</button></div>';
    const again = $("[data-sv-retry]", box);
    if (again) again.addEventListener("click", retry);
  }

  function kpi(icon, label, value, note) {
    return '<article class="card kpi">' +
      '<div class="kpi-top"><span class="kpi-ic">' + icon + "</span><b>" + esc(label) + "</b></div>" +
      '<div class="val num">' + esc(value) + "</div>" +
      '<div class="kpi-foot"><small>' + esc(note) + "</small></div></article>";
  }

  function table(columns, rows) {
    return '<div class="table-wrap"><table class="table sv-table"><thead><tr>' +
      columns.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr></thead><tbody>" + rows.join("") +
      "</tbody></table></div>";
  }
  /* One element per cell: on a phone a cell is a grid of its label and its content. */
  const cell = (label, html, cls) => '<td data-label="' + esc(label) + '"' + (cls ? ' class="' + cls + '"' : "") + ">" +
    '<div class="sv-cell">' + html + "</div></td>";
  const verdict = (v, score) => badge(v) + (score == null ? "" : '<span class="sv-sub mono">score ' + whole(score) + "</span>");

  /* A view's life: an AbortController for its requests, and listeners removed on the way out. */
  function life() {
    const controller = new AbortController();
    const off = [];
    return {
      signal: controller.signal,
      get alive() { return !controller.signal.aborted; },
      on(node, type, handler) { node.addEventListener(type, handler); off.push(() => node.removeEventListener(type, handler)); },
      end() { controller.abort(); off.forEach((undo) => undo()); }
    };
  }
  const get = (view, path) => request(path, { signal: view.signal });
  const quiet = (view, error) => !view.alive || (error && error.name === "AbortError");

  /* ─────────────────────────────────────────── Overview */
  function overview(session) {
    const name = session && session.user ? session.user.displayName : "";
    return {
      title: "Welcome back" + (name ? ", " + esc(name) : ""),
      sub: "Your workspace's cases, as they stand now.",
      body: () =>
        '<div class="kpis" id="sv-kpis" aria-busy="true">' + loading + "</div>" +
        '<div class="panel-row">' +
          '<section class="card panel" aria-labelledby="sv-findings-h">' +
            '<div class="panel-head"><h4 id="sv-findings-h">Finding overview</h4>' +
              '<div class="seg" role="group" aria-label="Filter cases">' +
                '<button type="button" data-sv-filter="all" aria-pressed="true">All</button>' +
                '<button type="button" data-sv-filter="open" aria-pressed="false">Open</button>' +
                '<button type="button" data-sv-filter="close" aria-pressed="false">Closed</button></div></div>' +
            '<div id="sv-bands">' + loading + "</div>" +
            '<div class="label-xs sv-gap">Latest indicators</div><div id="sv-latest">' + loading + "</div>" +
          "</section>" +
          '<section class="card panel" aria-labelledby="sv-trend-h">' +
            '<div class="panel-head"><h4 id="sv-trend-h">Cases over 90 days</h4></div>' +
            '<div id="sv-trend">' + loading + "</div>" +
          "</section></div>",
      mount(root, ctx) {
        const view = life();
        let model = null, filter = "all";

        function drawBands() {
          const box = $("#sv-bands", root);
          if (!model || model.total("all") === 0) {
            box.innerHTML = emptyState("No cases yet", toWorkbench);
            return;
          }
          const bands = model.severity(filter).filter((band) => band.n > 0);
          box.innerHTML = '<div class="label-xs">Severity</div>' +
            '<div class="sev" data-sv-sev>' + (bands.length
              ? bands.map((b) => '<span class="' + b.k + '" style="flex:' + b.n + ' 1 0">' + esc(b.text) + "</span>").join("")
              : '<span class="info" style="flex:1 1 0">None</span>') + "</div>" +
            '<div class="label-xs sv-gap">State</div><div class="state-row" data-sv-state>' +
              model.states(filter).map((st) => "<div>" + esc(st.text) + "</div>").join("") + "</div>";
        }

        function drawTrend(stats) {
          const days = objects(stats.trend);
          const weeks = [];
          for (let end = days.length; end > 0; end -= 7) weeks.unshift(days.slice(Math.max(0, end - 7), end));
          const opened = weeks.map((w) => w.reduce((n, d) => n + whole(d.opened), 0));
          const closed = weeks.map((w) => w.reduce((n, d) => n + whole(d.closed), 0));
          const peak = Math.max(1, ...opened);
          const ttc = stats.time_to_close || {};
          const label = (w) => (w[0] && typeof w[0].date === "string" ? w[0].date.slice(5) : "");
          $("#sv-trend", root).innerHTML = (opened.some(Boolean)
            ? '<div class="bars sv-bars" role="list" aria-label="Cases opened each week">' + weeks.map((w, i) => {
                const h = Math.max(2, Math.round((opened[i] / peak) * 100));
                return '<div class="col" role="listitem" tabindex="0" title="Week of ' + esc(label(w)) + ": " +
                  opened[i] + " opened, " + closed[i] + ' closed">' +
                  '<div class="stick" style="height:' + h + "%;--h:" + h + '%"></div>' +
                  '<span class="x">' + esc(label(w)) + "</span></div>";
              }).join("") + "</div>"
            : emptyState("Nothing opened in 90 days", toWorkbench)) +
            '<p class="wb-hint sv-gap">' + count(opened.reduce((a, b) => a + b, 0), "case") + " opened and " +
              whole(closed.reduce((a, b) => a + b, 0)) + " closed in 90 days. " +
              (whole(ttc.cases) ? "Closing takes " + duration(ttc.median_seconds) + " at the median (" +
                duration(ttc.mean_seconds) + " on average) over " + count(ttc.cases, "case") + "."
                : "No case has been closed yet, so there is no time to close.") + "</p>";
        }

        async function load() {
          try {
            const [stats, latest] = await Promise.all([get(view, "/api/stats"), get(view, "/api/indicators?limit=6")]);
            if (!view.alive) return;
            const s = stats && typeof stats === "object" ? stats : {};
            const by = s.by_status || {};
            const ttc = s.time_to_close || {};
            const closed90 = objects(s.trend).reduce((n, d) => n + whole(d.closed), 0);
            const kpis = $("#sv-kpis", root);
            kpis.removeAttribute("aria-busy");
            kpis.innerHTML =
              kpi(ctx.icon("i-search"), "Open cases", whole(s.open).toLocaleString(), count(s.unassigned_open, "unassigned", "unassigned")) +
              kpi(ctx.icon("i-flag"), "Awaiting triage", whole(by.new).toLocaleString(),
                s.assigned_to_me_open == null ? "new cases" : whole(s.assigned_to_me_open) + " open and assigned to you") +
              kpi(ctx.icon("i-check-circle"), "Closed, 90 days", closed90.toLocaleString(), count(s.cases, "case") + " in all") +
              kpi(ctx.icon("i-clock"), "Time to close", whole(ttc.cases) ? shortDuration(ttc.median_seconds) : "n/a",
                whole(ttc.cases) ? "median over " + count(ttc.cases, "case") : "no case closed yet");
            model = MODEL.from(s.bands);
            drawBands();
            drawTrend(s);
            const rows = objects(latest);
            $("#sv-latest", root).innerHTML = rows.length
              ? table(["Indicator", "Verdict", "Flagged by", "Last seen"], rows.map((r) => "<tr>" +
                  cell("Indicator", '<span class="mono">' + esc(r.value) + '</span><span class="sv-sub">' + esc(r.type) + "</span>") +
                  cell("Verdict", badge(r.verdict)) +
                  cell("Flagged by", esc(list(r.flagged_by).map(text).join(", ") || "none")) +
                  cell("Last seen", esc(when(r.last_seen)), "mono") + "</tr>"))
              : emptyState("No indicators yet", toWorkbench);
          } catch (error) {
            if (quiet(view, error)) return;
            failed($("#sv-bands", root), error, load);
            $("#sv-kpis", root).innerHTML = "";
            $("#sv-latest", root).innerHTML = "";
            $("#sv-trend", root).innerHTML = "";
          }
        }

        $$("[data-sv-filter]", root).forEach((button) => view.on(button, "click", () => {
          $$("[data-sv-filter]", root).forEach((b) => b.setAttribute("aria-pressed", String(b === button)));
          filter = button.dataset.svFilter;
          drawBands();
        }));
        load();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Attack surface */
  function surface() {
    return {
      title: "Attack surface",
      sub: "The hosts and people your pushed alerts name.",
      body: () =>
        '<div class="kpis" id="sv-kpis">' + loading + "</div>" +
        '<section class="card panel sv-gap" aria-labelledby="sv-assets-h">' +
          '<div class="panel-head"><h4 id="sv-assets-h">Named in alerts</h4></div>' +
          '<div id="sv-assets">' + loading + "</div></section>",
      mount(root, ctx) {
        const view = life();
        async function load() {
          try {
            const body = await get(view, "/api/assets?limit=200");
            if (!view.alive) return;
            const assets = objects(body && body.assets);
            const of = (kind) => assets.filter((a) => a.kind === kind).length;
            $("#sv-kpis", root).innerHTML =
              kpi(ctx.icon("i-grid"), "Hosts", of("host"), "named in pushed alerts") +
              kpi(ctx.icon("i-bot"), "People", of("user"), "accounts named") +
              kpi(ctx.icon("i-target"), "Other", assets.length - of("host") - of("user"), "addresses, files and the rest") +
              kpi(ctx.icon("i-flag"), "Alerts", whole(body && body.alerts_considered).toLocaleString(),
                body && body.truncated ? "the newest 2,000 read" : "pushed to this workspace");
            $("#sv-assets", root).innerHTML = assets.length
              ? table(["Name", "Kind", "Highest verdict", "Cases", "Last seen"], assets.map((a) => "<tr>" +
                  cell("Name", esc(a.name), "mono") + cell("Kind", esc(a.kind)) + cell("Highest verdict", badge(a.verdict)) +
                  cell("Cases", whole(a.cases) + " (" + whole(a.open_cases) + " open)") +
                  cell("Last seen", esc(when(a.last_seen)), "mono") + "</tr>"))
              : emptyState("No pushed alerts yet",
                  "A SIEM or EDR fills this view by pushing its alerts to <code>POST /api/alerts</code> with an " +
                  "API token of the <code>ingest</code> scope. Every host and account an alert names is listed here.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-assets", root), error, load);
          }
        }
        load();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Triage history and queue */
  function cases(kind) {
    const queue = kind === "queue";
    return () => ({
      title: queue ? "Triage queue" : "Triage history",
      sub: queue ? "Open cases, worst first." : "Every case in this workspace, newest first.",
      body: () =>
        (queue ? '<div class="kpis" id="sv-kpis">' + loading + "</div>" : "") +
        '<section class="card panel' + (queue ? " sv-gap" : "") + '" aria-labelledby="sv-cases-h">' +
          '<div class="panel-head"><h4 id="sv-cases-h">' + (queue ? "Open cases" : "Cases") + "</h4></div>" +
          (queue ? "" :
            '<form class="wb-row sv-filters" role="search" id="sv-search">' +
              '<label class="sr-only" for="sv-q">Search cases</label>' +
              '<input class="wb-field" id="sv-q" type="search" name="q" maxlength="200" autocomplete="off" ' +
                'placeholder="A title, or part of an indicator">' +
              '<label class="sr-only" for="sv-status">Status</label>' +
              '<select class="wb-field sv-select" id="sv-status" name="status">' +
                '<option value="">Any status</option><option value="open">Open</option>' +
                '<option value="new">Awaiting triage</option><option value="in_progress">In progress</option>' +
                '<option value="closed">Closed</option></select>' +
              '<label class="sr-only" for="sv-verdict">Verdict</label>' +
              '<select class="wb-field sv-select" id="sv-verdict" name="verdict"><option value="">Any verdict</option>' +
                BANDS.map((b) => '<option value="' + b + '">' + b + "</option>").join("") + "</select>" +
              '<label class="sr-only" for="sv-assignee">Assignee</label>' +
              '<select class="wb-field sv-select" id="sv-assignee" name="assignee"><option value="">Anyone</option>' +
                '<option value="me">Assigned to me</option><option value="none">Unassigned</option></select>' +
              '<button type="submit" class="btn btn-dark btn-sm">Search</button></form>') +
          '<div id="sv-cases">' + loading + "</div>" +
          '<div class="wb-row" id="sv-more-row" hidden><button type="button" class="btn btn-light btn-sm" id="sv-more">Show more</button></div>' +
          '<p class="wb-hint" id="sv-note" role="status"></p></section>',
      mount(root, ctx) {
        const view = life();
        const PAGE = queue ? 200 : 25;
        let offset = 0, rows = [], members = [], myId = 0;
        const note = (message) => { $("#sv-note", root).textContent = message; };

        function query() {
          const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
          if (queue) params.set("status", "open");
          const form = $("#sv-search", root);
          if (form) {
            for (const [key, value] of new FormData(form).entries()) {
              if (typeof value === "string" && value.trim()) params.set(key, value.trim());
            }
          }
          return "/api/cases?" + params.toString();
        }

        function controls(row) {
          const title = esc(row.title || "this case");
          const assignee = row.assignee && row.assignee.id;
          return '<label class="sr-only" for="sv-a-' + esc(row.id) + '">Assignee of ' + title + "</label>" +
            '<select class="wb-field sv-select" id="sv-a-' + esc(row.id) + '" data-assign="' + esc(row.id) + '">' +
              '<option value="">Unassigned</option>' +
              members.map((m) => '<option value="' + whole(m.id) + '"' + (whole(m.id) === assignee ? " selected" : "") + ">" +
                esc(m.display_name || m.username) + "</option>").join("") + "</select>" +
            '<label class="sr-only" for="sv-s-' + esc(row.id) + '">Status of ' + title + "</label>" +
            '<select class="wb-field sv-select" id="sv-s-' + esc(row.id) + '" data-status="' + esc(row.id) + '">' +
              '<option value="new"' + (row.status === "new" ? " selected" : "") + ">Awaiting triage</option>" +
              '<option value="in_progress"' + (row.status === "in_progress" ? " selected" : "") + ">In progress</option>" +
              Object.keys(REASONS).map((r) => '<option value="closed:' + r + '">Close: ' + REASONS[r] + "</option>").join("") +
            "</select>";
        }

        /* What a case was made from (tier 1): its state, and who may hold it or delete it. */
        function inputControls(row) {
          const user = me();
          const admin = user.role === "admin";
          const id = esc(row.id);
          const parts = [];
          if (row.held) parts.push('<span class="sv-sub">held: kept past retention</span>');
          if (row.input_deleted_at) parts.push('<span class="sv-sub">input deleted ' + esc(when(row.input_deleted_at)) + "</span>");
          else if (!row.held && (admin || (user.id && whole(row.created_by) === user.id))) {
            parts.push('<button type="button" class="btn btn-light btn-sm" data-drop-input="' + id + '">Delete input</button>');
          }
          if (admin) {
            parts.push('<button type="button" class="btn btn-light btn-sm" data-hold="' + id + '" data-held="' + (row.held ? "1" : "") + '">' +
              (row.held ? "Release" : "Hold") + "</button>");
            parts.push('<button type="button" class="btn btn-light btn-sm" data-delete-case="' + id + '">Delete case</button>');
          }
          return parts.length ? '<div class="sv-controls sv-gap-sm">' + parts.join("") + "</div>" : "";
        }

        function line(row) {
          const report = "/api/cases/" + encodeURIComponent(text(row.id)) + "/report?fmt=markdown";
          return '<tr data-case="' + esc(row.id) + '">' +
            cell("Case", esc(row.title || "Untitled triage") + '<span class="sv-sub mono">' + esc(text(row.id).slice(0, 8)) +
              " · " + esc(row.source) + "</span>", "sv-wide") +
            cell("Verdict", verdict(row.verdict, row.max_score)) +
            (queue
              ? cell("Work it", '<div class="sv-controls">' + controls(row) + "</div>")
              : cell("Status", esc(statusText(row))) +
                cell("Assignee", esc(row.assignee ? row.assignee.display_name || row.assignee.username : "nobody"))) +
            cell("Opened", esc(when(row.created_at)), "mono") +
            cell("Report", '<a class="wb-link" href="' + esc(report) + '" target="_blank" rel="noopener">Markdown</a>' +
              (queue ? "" : inputControls(row))) +
            "</tr>";
        }

        function draw() {
          const box = $("#sv-cases", root);
          const shown = queue
            ? rows.slice().sort((a, b) => (RANK[b.verdict] || 0) - (RANK[a.verdict] || 0) || whole(b.max_score) - whole(a.max_score))
            : rows;
          box.innerHTML = shown.length
            ? table(queue ? ["Case", "Verdict", "Work it", "Opened", "Report"] : ["Case", "Verdict", "Status", "Assignee", "Opened", "Report"],
                shown.map(line))
            : queue ? emptyState("Nothing waiting", "Every case is closed. New ones arrive from the workbench and from pushed alerts.")
              : emptyState("No cases match", offset || $("#sv-q", root)?.value ? "Try fewer words, or another filter." : toWorkbench);
          if (queue && rows.length >= PAGE) note("Showing the " + PAGE + " newest open cases.");
          if (queue) {
            const unassigned = rows.filter((r) => !r.assignee).length;
            const mine = rows.filter((r) => r.assignee && whole(r.assignee.id) === myId).length;
            $("#sv-kpis", root).innerHTML =
              kpi(ctx.icon("i-search"), "Open", rows.length, "awaiting triage or in progress") +
              kpi(ctx.icon("i-flag"), "Critical or high", rows.filter((r) => RANK[r.verdict] >= 3).length, "worth taking first") +
              kpi(ctx.icon("i-bot"), "Unassigned", unassigned, "nobody has taken them") +
              kpi(ctx.icon("i-check-circle"), "Yours", mine, "assigned to you");
          }
        }

        const me = () => (window.IntelPulseData.session && window.IntelPulseData.session.user) || {};

        async function load(more) {
          if (!more) { offset = 0; rows = []; }
          try {
            if (queue && !members.length) {
              members = objects(await get(view, "/api/users")).filter((m) => !m.disabled);
              const mine = members.find((m) => m.username === me().username);
              myId = mine ? whole(mine.id) : 0;
            }
            const page = objects(await get(view, query()));
            if (!view.alive) return;
            rows = rows.concat(page);
            offset += page.length;
            $("#sv-more-row", root).hidden = queue || page.length < PAGE;
            draw();
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-cases", root), error, () => load(false));
          }
        }

        async function change(id, body, select) {
          select.disabled = true;
          try {
            await request("/api/cases/" + encodeURIComponent(id), { method: "PATCH", body: JSON.stringify(body), signal: view.signal });
            if (!view.alive) return;
            ctx.toast("Case updated");
            note("");
            await load(false);
          } catch (error) {
            if (quiet(view, error)) return;
            select.disabled = false;
            note("Could not update the case: " + (error.message || "the server did not answer"));
          }
        }

        /* two presses, no dialog, for what cannot be undone */
        const armed = (button, label) => {
          if (button.dataset.armed === "1") return true;
          button.dataset.armed = "1";
          button.textContent = label;
          return false;
        };
        async function act(button, path, method, said) {
          button.disabled = true;
          try {
            await request(path, { method, signal: view.signal });
            if (!view.alive) return;
            ctx.toast(said);
            note("");
            await load(false);
          } catch (error) {
            if (quiet(view, error)) return;
            button.disabled = false;
            note("That did not work: " + (error.message || "the server did not answer"));
          }
        }
        view.on(root, "click", (event) => {
          const drop = event.target.closest("[data-drop-input]");
          if (drop) {
            if (armed(drop, "Press again to delete the input")) {
              act(drop, "/api/cases/" + encodeURIComponent(drop.dataset.dropInput) + "/input", "DELETE", "Input deleted; the verdict stays");
            }
            return;
          }
          const hold = event.target.closest("[data-hold]");
          if (hold) {
            const release = hold.dataset.held === "1";
            act(hold, "/api/cases/" + encodeURIComponent(hold.dataset.hold) + "/hold", release ? "DELETE" : "POST",
              release ? "Released: retention applies again" : "Held: kept past retention");
            return;
          }
          const gone = event.target.closest("[data-delete-case]");
          if (gone && armed(gone, "Press again to delete the case")) {
            act(gone, "/api/cases/" + encodeURIComponent(gone.dataset.deleteCase), "DELETE", "Case deleted");
          }
        });
        view.on(root, "change", (event) => {
          const target = event.target;
          if (target.matches("[data-assign]")) {
            change(target.dataset.assign, { assignee_id: target.value ? whole(target.value) : null }, target);
          } else if (target.matches("[data-status]")) {
            const [status, reason] = target.value.split(":");
            change(target.dataset.status, reason ? { status, closed_reason: reason } : { status }, target);
          }
        });
        const form = $("#sv-search", root);
        if (form) view.on(form, "submit", (event) => { event.preventDefault(); load(false); });
        view.on($("#sv-more", root), "click", () => load(true));
        load(false);
        return () => view.end();
      }
    });
  }

  /* ─────────────────────────────────────────── All indicators */
  function indicators() {
    return {
      title: "All indicators",
      sub: "Each indicator once, with its latest verdict.",
      body: () =>
        '<section class="card panel" aria-labelledby="sv-ind-h">' +
          '<div class="panel-head"><h4 id="sv-ind-h">Indicators</h4></div>' +
          '<form class="wb-row sv-filters" role="search" id="sv-search">' +
            '<label class="sr-only" for="sv-q">Search indicators</label>' +
            '<input class="wb-field" id="sv-q" type="search" name="q" maxlength="200" autocomplete="off" placeholder="Part of an address, domain or hash">' +
            '<label class="sr-only" for="sv-verdict">Verdict</label>' +
            '<select class="wb-field sv-select" id="sv-verdict" name="verdict"><option value="">Any verdict</option>' +
              BANDS.map((b) => '<option value="' + b + '">' + b + "</option>").join("") + "</select>" +
            '<label class="sr-only" for="sv-sort">Sort by</label>' +
            '<select class="wb-field sv-select" id="sv-sort" name="sort">' +
              '<option value="last_seen">Last seen</option><option value="score">Score</option><option value="cases">Cases</option></select>' +
            '<button type="submit" class="btn btn-dark btn-sm">Search</button></form>' +
          '<div id="sv-ind">' + loading + "</div>" +
          '<div class="wb-row" id="sv-more-row" hidden><button type="button" class="btn btn-light btn-sm" id="sv-more">Show more</button></div>' +
        "</section>",
      mount(root) {
        const view = life();
        const PAGE = 50;
        let offset = 0, rows = [];
        async function load(more) {
          if (!more) { offset = 0; rows = []; }
          const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
          for (const [key, value] of new FormData($("#sv-search", root)).entries()) {
            if (typeof value === "string" && value.trim()) params.set(key, value.trim());
          }
          try {
            const page = objects(await get(view, "/api/indicators?" + params.toString()));
            if (!view.alive) return;
            rows = rows.concat(page);
            offset += page.length;
            $("#sv-more-row", root).hidden = page.length < PAGE;
            $("#sv-ind", root).innerHTML = rows.length
              ? table(["Indicator", "Verdict", "Cases", "Flagged by", "First seen", "Last seen"], rows.map((r) => "<tr>" +
                  cell("Indicator", esc(r.value) + '<span class="sv-sub">' + esc(r.type) +
                    (list(r.malware_families).length ? " · " + esc(list(r.malware_families).map(text).join(", ")) : "") + "</span>", "mono sv-wide") +
                  cell("Verdict", verdict(r.verdict, r.score)) +
                  cell("Cases", String(whole(r.cases))) +
                  cell("Flagged by", esc(list(r.flagged_by).map(text).join(", ") || "none")) +
                  cell("First seen", esc(when(r.first_seen)), "mono") + cell("Last seen", esc(when(r.last_seen)), "mono") + "</tr>"))
              : emptyState("No indicators match", $("#sv-q", root).value ? "Try another part of the value." : toWorkbench);
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-ind", root), error, () => load(false));
          }
        }
        view.on($("#sv-search", root), "submit", (event) => { event.preventDefault(); load(false); });
        view.on($("#sv-more", root), "click", () => load(true));
        load(false);
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Campaign graph */
  /* A campaign as the graph component draws it (console-panes.js, the same one the
     demo uses): the campaign is the hub, each thing its cases share is a cluster,
     and a cluster's members are the cases that share it. Two clusters are linked
     when a case shares both. Every number is made here; every text is the
     server's and is escaped, or set as text, where the graph draws it. */
  const GRAPH_KIND = { malware: "malware", indicator: "ioc", infrastructure: "infra" };
  const verdictIn = (v) => (BANDS.includes(v) ? v : "informational");
  function graphData(c) {
    const titleOf = new Map(objects(c.cases).map((k) => [text(k.id), text(k.title) || text(k.id).slice(0, 8)]));
    const total = Math.max(1, whole(c.case_count));
    const now = new Date().getFullYear();
    const year = (iso) => { const y = parseInt(text(iso).slice(0, 4), 10); return y >= 1970 && y <= now + 1 ? y : now; };
    const clusters = objects(c.links).slice(0, 12).map((l, i) => {
      const ids = list(l.cases).map(text).filter(Boolean);
      return { id: "k" + i, label: text(l.value) || "shared", kind: GRAPH_KIND[l.kind] || "infra",
        pct: Math.max(1, Math.min(100, Math.round((ids.length / total) * 100))), seen: year(l.first_seen),
        nodes: Math.min(12, ids.length), sev: verdictIn(l.verdict), ids: ids };
    });
    const links = [];
    clusters.forEach((a, i) => clusters.slice(i + 1).forEach((b) => {
      if (a.ids.some((id) => b.ids.includes(id))) links.push([a.id, b.id]);
    }));
    const members = {};
    clusters.forEach((k) => { members[k.id] = k.ids.slice(0, 12).map((id) => titleOf.get(id) || id.slice(0, 8)); });
    const years = Array.from(new Set(clusters.map((k) => k.seen))).sort((a, b) => a - b);
    const label = text(c.label) || "Campaign";
    return {
      hub: { label: label, sub: count(c.case_count, "case"), seen: years.length ? years[0] : year(c.first_seen), sev: verdictIn(c.verdict) },
      title: label + " · what this campaign is built from",
      aria: "Relationship graph of the campaign " + label + " in this workspace",
      note: "From this workspace's cases of the last 90 days. A cluster is something two or more of them share; its members are those cases.",
      clusters: clusters.map((k) => ({ id: k.id, label: k.label, kind: k.kind, pct: k.pct, seen: k.seen, nodes: k.nodes, sev: k.sev })),
      links: links, years: years.length ? years : [now], members: members
    };
  }

  function campaignCases(c) {
    return '<section class="card panel sv-card sv-gap" aria-labelledby="sv-cc-h">' +
      '<div class="panel-head"><h4 id="sv-cc-h">Its cases</h4>' + badge(c.verdict) + "</div>" +
      '<p class="wb-hint">' + count(c.case_count, "case") + ", " + esc(when(c.first_seen)) + " to " + esc(when(c.last_seen)) + ". Shared: " +
        objects(c.links).slice(0, 6).map((l) => "<strong>" + esc(l.value) + "</strong> (" + esc(l.kind) + ", " +
          count(list(l.cases).length, "case") + ")").join(", ") + ".</p>" +
      table(["Case", "Verdict", "Status", "Opened"], objects(c.cases).map((k) => "<tr>" +
        cell("Case", esc(k.title), "sv-wide") + cell("Verdict", badge(k.verdict)) +
        cell("Status", esc(STATUS[k.status] || "")) + cell("Opened", esc(when(k.created_at)), "mono") + "</tr>")) +
      "</section>";
  }

  function campaigns() {
    const graph = window.IntelPulsePanes && window.IntelPulsePanes.graph;
    return {
      title: "Campaign graph",
      sub: "Cases that share a family or infrastructure.",
      body: () => '<div id="sv-campaigns">' + loading + "</div>",
      mount(root, ctx) {
        const view = life();
        let found = [], unmountGraph = null;
        const leaveGraph = () => {
          if (!unmountGraph) return;
          const done = unmountGraph;
          unmountGraph = null;
          try { done(); } catch (_) { /* the graph is going either way */ }
        };

        function show(index) {
          leaveGraph();
          const c = found[index] || found[0];
          const host = $("#sv-graph", root);
          if (graph && host) {
            const data = graphData(c);
            host.innerHTML = graph.body(data);
            unmountGraph = graph.mount(host, ctx, data) || null;
          }
          $("#sv-campaign-cases", root).innerHTML = campaignCases(c);
        }

        async function load() {
          try {
            const body = await get(view, "/api/campaigns");
            if (!view.alive) return;
            found = objects(body && body.campaigns);
            const box = $("#sv-campaigns", root);
            if (!found.length) {
              box.innerHTML = '<section class="card panel">' + emptyState("No campaign yet",
                "Two cases become a campaign when they share a malware family, an indicator or infrastructure " +
                "such as an ASN. " + toWorkbench) + "</section>";
              return;
            }
            box.innerHTML = (found.length > 1
              ? '<div class="wb-row sv-pick"><label class="label-xs" for="sv-pick">Campaign</label>' +
                '<select class="wb-field sv-select" id="sv-pick">' + found.map((c, i) => '<option value="' + i + '">' +
                  esc(c.label) + " · " + count(c.case_count, "case") + " · " + esc(c.verdict) + "</option>").join("") + "</select></div>"
              : "") +
              '<div id="sv-graph"></div><div id="sv-campaign-cases"></div>';
            const pick = $("#sv-pick", root);
            if (pick) view.on(pick, "change", () => show(whole(pick.value)));
            show(0);
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-campaigns", root), error, load);
          }
        }
        load();
        return () => { leaveGraph(); view.end(); };
      }
    };
  }

  /* ─────────────────────────────────────────── Attack narratives */
  function narratives() {
    return {
      title: "Attack narratives",
      sub: "Each case's techniques, in the order they run.",
      body: () => '<div id="sv-stories">' + loading + "</div>",
      mount(root) {
        const view = life();
        async function load() {
          try {
            const body = await get(view, "/api/narratives");
            if (!view.alive) return;
            const stories = objects(body && body.narratives);
            $("#sv-stories", root).innerHTML = stories.length
              ? stories.map((story) => {
                  const c = story.case || {};
                  return '<section class="card panel sv-card">' +
                    '<div class="panel-head"><h4>' + esc(c.title || "Untitled triage") + "</h4>" + badge(c.verdict) + "</div>" +
                    '<ol class="sv-steps">' + objects(story.steps).map((step) => "<li><b>" + esc(step.tactic) + "</b><ul>" +
                      objects(step.techniques).map((t) => {
                        const href = safeUrl(t.url);
                        const name = esc(t.id) + " " + esc(t.name);
                        const evidence = objects(t.evidence).map((e) => '<span class="mono">' + esc(e.indicator) + "</span>" +
                          (list(e.named_by).length ? " (" + esc(list(e.named_by).map(text).join(", ") + ")") : " (inferred from tags)"));
                        return "<li>" + (href ? '<a class="wb-link" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + name + "</a>" : name) +
                          (evidence.length ? ": " + evidence.join(", ") : "") +
                          (t.from_alert ? ' <span class="sv-sub">named by the pushed alert</span>' : "") + "</li>";
                      }).join("") + "</ul></li>").join("") + "</ol></section>";
                }).join("")
              : '<section class="card panel">' + emptyState("No narrative yet",
                  "A case tells a story once a provider or a pushed alert names an ATT&amp;CK technique. " + toWorkbench) +
                "</section>";
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-stories", root), error, load);
          }
        }
        load();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Intelligence sources */
  function sources(guide) {
    return {
      title: "Intelligence sources",
      sub: "What each source answered this week.",
      body: () =>
        '<section class="card panel" aria-labelledby="sv-src-h">' +
          '<div class="panel-head"><h4 id="sv-src-h">This workspace\'s sources, last 7 days</h4></div>' +
          '<div id="sv-sources">' + loading + "</div></section>" +
        '<section class="card panel sv-gap" aria-labelledby="sv-feeds-h">' +
          '<div class="panel-head"><h4 id="sv-feeds-h">Offline feeds, shared by the server</h4></div>' +
          '<div id="sv-feeds">' + loading + "</div></section>" +
        '<div class="sv-gap">' + guide() + "</div>",
      mount(root) {
        const view = life();
        async function load() {
          try {
            const body = await get(view, "/api/sources");
            if (!view.alive) return;
            const providers = objects(body && body.providers);
            $("#sv-sources", root).innerHTML = table(["Source", "State", "Asked", "Errors", "Median", "Last error"],
              providers.map((p) => {
                const state = !p.enabled ? "Off" : p.needs_key && !p.key_set ? "On, no key: skipped" : "On";
                const last = p.last_error && typeof p.last_error === "object"
                  ? esc(text(p.last_error.message) || text(p.last_error.status)) + '<span class="sv-sub">' + esc(when(p.last_error.at)) + "</span>"
                  : "none";
                return "<tr>" + cell("Source", esc(p.label || p.name)) + cell("State", esc(state)) +
                  cell("Asked", whole(p.queries) + " (" + whole(p.answered) + " answered)") +
                  cell("Errors", whole(p.errors) + (whole(p.rate_limited) ? ", " + whole(p.rate_limited) + " rate limited" : "")) +
                  cell("Median", p.median_latency_ms == null ? "n/a" : whole(p.median_latency_ms) + " ms", "mono") +
                  cell("Last error", last, "sv-wide") + "</tr>";
              }));
            const feeds = objects(body && body.feeds);
            $("#sv-feeds", root).innerHTML = feeds.length
              ? table(["Feed", "Rows", "Last refresh", "State"], feeds.map((f) => "<tr>" +
                  cell("Feed", esc(f.feed), "mono") + cell("Rows", whole(f.stored_rows).toLocaleString()) +
                  cell("Last refresh", esc(when(f.ran_at)), "mono") + cell("State", f.ok ? "ok" : esc("failed: " + text(f.detail))) + "</tr>"))
              : emptyState("No feed imported", "The server's owner imports the offline feeds with <code>make feeds</code>.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-sources", root), error, load);
          }
        }
        load();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── SOC tickets */
  function tickets() {
    return {
      title: "SOC tickets",
      sub: "Tickets raised for your cases, with their evidence.",
      body: () => '<section class="card panel" aria-labelledby="sv-tk-h">' +
        '<div class="panel-head"><h4 id="sv-tk-h">Tickets</h4></div><div id="sv-tickets">' + loading + "</div></section>",
      mount(root) {
        const view = life();
        async function load() {
          try {
            const rows = objects(await get(view, "/api/tickets?limit=200"));
            if (!view.alive) return;
            $("#sv-tickets", root).innerHTML = rows.length
              ? table(["Ticket", "Case", "Raised by", "When", "Evidence"], rows.map((t) => {
                  const href = safeUrl(t.url);
                  const key = esc(t.key) + '<span class="sv-sub">' + (t.sink === "servicenow" ? "ServiceNow" : "Jira") + "</span>";
                  const c = t.case || {};
                  const report = t.report || {};
                  const local = (path) => (typeof path === "string" && /^\/api\/cases\/[^/?#]+\/report\?fmt=(markdown|json)$/.test(path) ? path : null);
                  const links = [["Markdown", local(report.markdown)], ["JSON", local(report.json)]]
                    .filter(([, path]) => path)
                    .map(([label, path]) => '<a class="wb-link" href="' + esc(path) + '" target="_blank" rel="noopener">' + label + "</a>");
                  return "<tr>" + cell("Ticket", href ? '<a class="wb-link" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + key + "</a>" : key) +
                    cell("Case", esc(c.title || "") + " " + badge(c.verdict), "sv-wide") +
                    cell("Raised by", esc(t.created_by ? t.created_by.display_name || t.created_by.username : "not recorded")) +
                    cell("When", esc(when(t.created_at)), "mono") + cell("Evidence", links.join(" · ") || "none") + "</tr>";
                }))
              : emptyState("No tickets yet",
                  "Raise one from a case in the workbench once an admin connects Jira or ServiceNow in the workspace settings.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#sv-tickets", root), error, load);
          }
        }
        load();
        return () => view.end();
      }
    };
  }

  /* The pieces the workspace panes (console-admin.js) build with, so both files
     escape, fetch, fail and empty the same way. */
  window.IntelPulseServerKit = {
    esc, safeUrl, badge, when, whole, text, list, objects, count, table, cell, kpi, emptyState, failed,
    loading, life, get, quiet, request
  };

  /* name -> (session, helpers) => view. suite.js asks for a view only when signed in. */
  window.IntelPulseServerViews = {
    dashboard: (session) => overview(session),
    surface: () => surface(),
    activity: cases("history"),
    triage: cases("queue"),
    "all-findings": () => indicators(),
    campaigns: () => campaigns(),
    narratives: () => narratives(),
    sources: (session, helpers) => sources(helpers.sourcesGuide),
    tickets: () => tickets()
  };
})();
