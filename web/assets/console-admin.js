/* IntelPulse · the workspace's own panes, on a server (spec 9.3).
 *
 * Settings, Team and API tokens are an admin's; Audit and Profile are everyone's.
 * Each pane is a view like the others in console-server.js, built with the same
 * kit, and talks to the endpoints the API already guards: a pane only shows what
 * the server answered, and a refusal is shown in the server's own words.
 *
 * Secrets travel one way. A provider key, a tracker token, a new password or a
 * member's first password is read from its field, sent once and the field
 * cleared; nothing comes back but "set" and the last four characters. An API
 * token is the one exception the API makes, and it is shown once, in a field
 * the person copies from, and never kept by the page.
 */
(function () {
  "use strict";

  const K = window.IntelPulseServerKit;
  const views = window.IntelPulseServerViews;
  if (!K || !views) return;
  const { esc, when, whole, text, list, objects, table, cell, emptyState, failed, loading, life, get, quiet, request } = K;
  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const $$ = (sel, scope) => Array.from((scope || document).querySelectorAll(sel));
  const send = (view, path, method, body) =>
    request(path, { method, body: body === undefined ? undefined : JSON.stringify(body), signal: view.signal });
  const session = () => (window.IntelPulseData && window.IntelPulseData.session) || {};
  const isAdmin = () => Boolean(session().user && session().user.role === "admin");

  /* A form's fields as text, trimmed; a password is left exactly as typed. */
  function fields(form) {
    const out = {};
    for (const [key, value] of new FormData(form).entries()) {
      const input = form.elements[key];
      out[key] = typeof value !== "string" ? "" : input && input.type === "password" ? value : value.trim();
    }
    return out;
  }

  /* Run one change: disable the button, say what happened in the pane's status line. */
  async function act(view, status, button, work, done) {
    if (button) button.disabled = true;
    status.textContent = "";
    status.classList.remove("sv-bad");
    try {
      const answer = await work();
      if (!view.alive) return;
      status.textContent = done(answer) || "";
    } catch (error) {
      if (quiet(view, error)) return;
      status.classList.add("sv-bad");
      status.textContent = error && error.message ? error.message : "That did not work. Try again.";
    } finally {
      if (button && view.alive) button.disabled = false;
    }
  }

  const field = (id, label, attrs, hint) =>
    '<div class="sv-field"><label class="label-xs" for="' + id + '">' + label + "</label>" +
    '<input class="wb-field" id="' + id + '" ' + attrs + (hint ? ' aria-describedby="' + id + '-hint"' : "") + ">" +
    (hint ? '<p class="wb-hint" id="' + id + '-hint">' + hint + "</p>" : "") + "</div>";
  const statusLine = (id) => '<p class="wb-hint sv-status" id="' + id + '" role="status" aria-live="polite"></p>';
  const adminOnly = (what) => '<section class="card panel">' +
    emptyState("Only an admin can " + what, "Ask an admin of this workspace.") + "</section>";

  /* ─────────────────────────────────────────── Settings */
  function settings() {
    return {
      title: "Workspace settings",
      sub: "Sources and keys, trackers, retention and lists.",
      body: () => !isAdmin() ? adminOnly("change the workspace's settings") :
        '<section class="card panel" aria-labelledby="st-prov-h"><div class="panel-head"><h4 id="st-prov-h">Sources</h4></div>' +
          '<p class="wb-hint">A source that is off is never asked. One that needs a key and has none reports skipped, never clean.</p>' +
          '<div id="st-providers">' + loading + "</div>" + statusLine("st-prov-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="st-keys-h"><div class="panel-head"><h4 id="st-keys-h">Provider keys</h4></div>' +
          '<p class="wb-hint">Sealed on the server and never shown again: only whether one is set, and its last four characters.</p>' +
          '<div id="st-keys">' + loading + "</div>" + statusLine("st-keys-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="st-tk-h"><div class="panel-head"><h4 id="st-tk-h">Ticket trackers</h4></div>' +
          '<div id="st-trackers">' + loading + "</div>" + statusLine("st-tk-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="st-ret-h"><div class="panel-head"><h4 id="st-ret-h">Retention</h4></div>' +
          '<form id="st-retention" class="wb-row">' +
            field("st-days", "Days a case's input is kept", 'type="number" name="retention_days" min="1" max="365" required inputmode="numeric"',
              "1 to 365. The sweep that applies it arrives with the next release; the verdict and indicators stay.") +
            '<button type="submit" class="btn btn-dark btn-sm">Save</button></form>' + statusLine("st-ret-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="st-lists-h"><div class="panel-head"><h4 id="st-lists-h">Allow and block lists</h4></div>' +
          '<p class="wb-hint">An entry overrides every source: allowed reads informational, blocked reads critical.</p>' +
          '<form id="st-list-add" class="wb-row">' +
            '<label class="sr-only" for="st-list-value">Indicator</label>' +
            '<input class="wb-field" id="st-list-value" name="value" maxlength="2048" required placeholder="An address, domain, URL or hash" autocomplete="off">' +
            '<label class="sr-only" for="st-list-type">List</label>' +
            '<select class="wb-field sv-select" id="st-list-type" name="list_type"><option value="allow">Allow</option><option value="block">Block</option></select>' +
            '<label class="sr-only" for="st-list-reason">Reason</label>' +
            '<input class="wb-field" id="st-list-reason" name="reason" maxlength="500" placeholder="Why (kept with the entry)" autocomplete="off">' +
            '<button type="submit" class="btn btn-dark btn-sm">Add</button></form>' +
          '<div id="st-lists">' + loading + "</div>" + statusLine("st-lists-status") + "</section>",
      mount(root) {
        if (!isAdmin()) return null;
        const view = life();
        let current = null;

        function drawProviders() {
          $("#st-providers", root).innerHTML = table(["Source", "Checks", "Key", "On", "Test"], objects(current.providers).map((p) => {
            const key = !p.requires_key ? "not needed" : p.key_set ? "set" : "missing";
            return "<tr>" + cell("Source", esc(p.label)) + cell("Checks", esc(list(p.supported_types).map(text).join(", "))) +
              cell("Key", esc(key)) +
              cell("On", '<label class="sv-switch"><input type="checkbox" data-provider="' + esc(p.name) + '"' +
                (p.enabled ? " checked" : "") + '><span class="sr-only">Ask ' + esc(p.label) + "</span></label>") +
              cell("Test", '<button type="button" class="btn btn-light btn-sm" data-test="' + esc(p.name) + '">Test</button>') + "</tr>";
          }));
        }

        function drawKeys() {
          const keys = current.keys && typeof current.keys === "object" ? current.keys : {};
          $("#st-keys", root).innerHTML = Object.keys(keys).map((slot) => {
            const k = keys[slot] || {};
            const id = "st-key-" + esc(slot);
            return '<form class="wb-row sv-key" data-key="' + esc(slot) + '">' +
              '<div class="sv-field"><label class="label-xs" for="' + id + '">' + esc(k.label || slot) + "</label>" +
              '<input class="wb-field" id="' + id + '" type="password" name="value" maxlength="512" autocomplete="off" ' +
                'placeholder="' + (k.set ? "Set: " + esc(k.hint || "") : "Not set") + '"></div>' +
              '<button type="submit" class="btn btn-dark btn-sm">' + (k.set ? "Replace" : "Save") + "</button>" +
              (k.set ? '<button type="button" class="btn btn-light btn-sm" data-key-remove="' + esc(slot) + '">Remove</button>' : "") +
              "</form>";
          }).join("");
        }

        function drawTrackers() {
          const t = current.tickets || {};
          const jira = t.jira || {}, sn = t.servicenow || {};
          const secret = (s) => (s && s.set ? "Set: " + esc(s.hint || "") + ". Leave empty to keep it." : "Not set");
          const value = (v) => ' value="' + esc(v || "") + '"';
          $("#st-trackers", root).innerHTML =
            '<form class="sv-tracker" data-sink="jira"><h5>Jira' + (list(t.configured).includes("jira") ? " · ready" : "") + "</h5>" +
              field("st-jira-url", "Address", 'type="url" name="base_url" placeholder="https://acme.atlassian.net"' + value(jira.base_url)) +
              field("st-jira-email", "Account email", 'type="email" name="email" autocomplete="off"' + value(jira.email)) +
              field("st-jira-project", "Project key", 'type="text" name="project_key" placeholder="SOC"' + value(jira.project_key)) +
              field("st-jira-type", "Issue type", 'type="text" name="issue_type"' + value(jira.issue_type)) +
              field("st-jira-token", "API token", 'type="password" name="api_token" maxlength="512" autocomplete="off" placeholder="' + secret(jira.api_token) + '"') +
              '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Save Jira</button>' +
                (jira.api_token && jira.api_token.set ? '<label class="sv-check"><input type="checkbox" name="remove_secret"> Remove the token</label>' : "") +
              "</div></form>" +
            '<form class="sv-tracker sv-gap" data-sink="servicenow"><h5>ServiceNow' + (list(t.configured).includes("servicenow") ? " · ready" : "") + "</h5>" +
              field("st-sn-url", "Address", 'type="url" name="base_url" placeholder="https://acme.service-now.com"' + value(sn.base_url)) +
              field("st-sn-user", "User", 'type="text" name="user" autocomplete="off"' + value(sn.user)) +
              field("st-sn-table", "Table", 'type="text" name="table"' + value(sn.table)) +
              field("st-sn-password", "Password", 'type="password" name="password" maxlength="512" autocomplete="off" placeholder="' + secret(sn.password) + '"') +
              '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Save ServiceNow</button>' +
                (sn.password && sn.password.set ? '<label class="sv-check"><input type="checkbox" name="remove_secret"> Remove the password</label>' : "") +
              "</div></form>";
        }

        async function loadLists() {
          try {
            const rows = objects(await get(view, "/api/lists"));
            if (!view.alive) return;
            $("#st-lists", root).innerHTML = rows.length
              ? table(["Indicator", "List", "Reason", "Added", "Remove"], rows.map((r) => "<tr>" +
                  cell("Indicator", '<span class="mono">' + esc(r.value) + '</span><span class="sv-sub">' + esc(r.ioc_type) + "</span>") +
                  cell("List", esc(r.list_type)) + cell("Reason", esc(r.reason || "none")) + cell("Added", esc(when(r.created_at)), "mono") +
                  cell("Remove", '<button type="button" class="btn btn-light btn-sm" data-list-remove="' + whole(r.id) + '">Remove</button>') + "</tr>"))
              : emptyState("No entries", "Add one above, or from a result in the workbench.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#st-lists", root), error, loadLists);
          }
        }

        async function load() {
          try {
            current = await get(view, "/api/settings");
            if (!view.alive) return;
            current = current && typeof current === "object" ? current : {};
            drawProviders();
            drawKeys();
            drawTrackers();
            $("#st-days", root).value = whole(current.retention_days) || 30;
          } catch (error) {
            if (!quiet(view, error)) failed($("#st-providers", root), error, load);
          }
        }

        const patch = (body) => send(view, "/api/settings", "PATCH", body);
        const changedText = (answer) => (answer && list(answer.changed).length === 0 ? "Nothing changed." : "Saved.");

        view.on(root, "change", (event) => {
          const box = event.target.closest("[data-provider]");
          if (!box) return;
          const name = box.dataset.provider;
          act(view, $("#st-prov-status", root), box, () => patch({ providers: { [name]: { enabled: box.checked } } }),
            () => (box.checked ? "On: " : "Off: ") + name + ".");
        });
        view.on(root, "click", (event) => {
          const test = event.target.closest("[data-test]");
          if (test) {
            act(view, $("#st-prov-status", root), test,
              () => send(view, "/api/settings/providers/" + encodeURIComponent(test.dataset.test) + "/test", "POST"),
              (a) => text(a && a.provider) + " answered " + text(a && a.status) + (a && a.error ? ": " + text(a.error) : "") +
                (a && a.latency_ms ? " in " + whole(a.latency_ms) + " ms" : "") + ".");
            return;
          }
          const remove = event.target.closest("[data-key-remove]");
          if (remove) {
            act(view, $("#st-keys-status", root), remove, () => patch({ keys: { [remove.dataset.keyRemove]: "" } }),
              () => { load(); return "Key removed."; });
            return;
          }
          const drop = event.target.closest("[data-list-remove]");
          if (drop) {
            act(view, $("#st-lists-status", root), drop, () => send(view, "/api/lists/" + whole(drop.dataset.listRemove), "DELETE"),
              () => { loadLists(); return "Entry removed."; });
          }
        });
        view.on(root, "submit", (event) => {
          const form = event.target;
          event.preventDefault();
          const submit = $("button[type=submit]", form);
          if (form.matches("[data-key]")) {
            const value = form.elements.value.value;
            if (!value) { $("#st-keys-status", root).textContent = "Paste the key first."; return; }
            act(view, $("#st-keys-status", root), submit, () => patch({ keys: { [form.dataset.key]: value } }),
              () => { form.elements.value.value = ""; load(); return "Key saved."; });
          } else if (form.matches("[data-sink]")) {
            const sink = form.dataset.sink;
            const values = fields(form);
            const secretName = sink === "jira" ? "api_token" : "password";
            const body = {};
            for (const [key, value] of Object.entries(values)) {
              if (key === "remove_secret" || key === secretName) continue;
              body[key] = value;
            }
            if (values.remove_secret) body[secretName] = "";
            else if (values[secretName]) body[secretName] = values[secretName];
            act(view, $("#st-tk-status", root), submit, () => patch({ tickets: { [sink]: body } }),
              (answer) => { load(); return changedText(answer); });
          } else if (form.id === "st-retention") {
            act(view, $("#st-ret-status", root), submit, () => patch({ retention_days: whole(form.elements.retention_days.value) }),
              (answer) => changedText(answer));
          } else if (form.id === "st-list-add") {
            const values = fields(form);
            act(view, $("#st-lists-status", root), submit,
              () => send(view, "/api/lists", "POST", { value: values.value, list_type: values.list_type, reason: values.reason }),
              () => { form.reset(); loadLists(); return "Added."; });
          }
        });
        load();
        loadLists();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Team */
  function team() {
    return {
      title: "Team",
      sub: "Who works in this workspace, and as what.",
      body: () => !isAdmin() ? adminOnly("manage the team") :
        '<section class="card panel" aria-labelledby="tm-h"><div class="panel-head"><h4 id="tm-h">Members</h4></div>' +
          '<div id="tm-list">' + loading + "</div>" + statusLine("tm-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="tm-add-h"><div class="panel-head"><h4 id="tm-add-h">Add a member</h4></div>' +
          '<p class="wb-hint">You set their first password; they choose their own when they first sign in.</p>' +
          '<form id="tm-add" class="sv-grid">' +
            field("tm-username", "Username", 'type="text" name="username" required maxlength="64" autocapitalize="none" spellcheck="false" autocomplete="off"',
              "3 to 64 lowercase letters, digits, dots, dashes or underscores.") +
            field("tm-name", "Display name", 'type="text" name="display_name" maxlength="120" autocomplete="off"') +
            '<div class="sv-field"><label class="label-xs" for="tm-role">Role</label>' +
              '<select class="wb-field sv-select" id="tm-role" name="role"><option value="analyst">Analyst</option><option value="admin">Admin</option></select></div>' +
            field("tm-password", "First password", 'type="password" name="password" required minlength="12" maxlength="1024" autocomplete="new-password"',
              "At least 12 characters.") +
            '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Add member</button></div></form>' +
          statusLine("tm-add-status") + "</section>",
      mount(root) {
        if (!isAdmin()) return null;
        const view = life();
        const me = () => (session().user || {}).username;
        const owner = () => Boolean((session().user || {}).owner);

        function row(m) {
          const self = m.username === me();
          const id = whole(m.id);
          const state = m.disabled ? "disabled" : m.must_change_password ? "must choose a password" : "active";
          const role = m.owner ? "owner (admin)" : esc(m.role);
          const canRole = !m.owner && !self;
          const actions = [];
          if (!m.owner && !self) {
            actions.push('<button type="button" class="btn btn-light btn-sm" data-toggle="' + id + '" data-disabled="' + (m.disabled ? "1" : "") + '">' +
              (m.disabled ? "Enable" : "Disable") + "</button>");
          }
          if (!m.owner && (m.role !== "admin" || owner()) && !self) {
            actions.push('<button type="button" class="btn btn-light btn-sm" data-reset="' + id + '">Reset password</button>');
          }
          if (!m.owner && !self) {
            actions.push('<button type="button" class="btn btn-light btn-sm" data-remove="' + id + '">Remove</button>');
          }
          return '<tr data-member="' + id + '">' +
            cell("Member", esc(m.display_name || m.username) + '<span class="sv-sub mono">' + esc(m.username) + (self ? " · you" : "") + "</span>") +
            cell("Role", canRole
              ? '<label class="sr-only" for="tm-r-' + id + '">Role of ' + esc(m.username) + '</label><select class="wb-field sv-select" id="tm-r-' + id +
                '" data-role="' + id + '"><option value="analyst"' + (m.role === "analyst" ? " selected" : "") + '>Analyst</option><option value="admin"' +
                (m.role === "admin" ? " selected" : "") + ">Admin</option></select>"
              : role) +
            cell("State", esc(state)) + cell("Last sign-in", esc(when(m.last_login_at)), "mono") +
            cell("Actions", actions.length ? '<div class="sv-controls">' + actions.join("") + "</div>" : "none") + "</tr>" +
            '<tr class="sv-reset-row" data-reset-row="' + id + '" hidden><td colspan="5"><form class="wb-row" data-reset-form="' + id + '">' +
              '<label class="sr-only" for="tm-p-' + id + '">New password for ' + esc(m.username) + "</label>" +
              '<input class="wb-field" id="tm-p-' + id + '" type="password" name="password" minlength="12" maxlength="1024" autocomplete="new-password" placeholder="A new password, 12 characters or more">' +
              '<button type="submit" class="btn btn-dark btn-sm">Set it</button>' +
              '<span class="wb-hint">Their sessions end; they choose their own at the next sign-in.</span></form></td></tr>';
        }

        async function load() {
          try {
            const members = objects(await get(view, "/api/users"));
            if (!view.alive) return;
            $("#tm-list", root).innerHTML = table(["Member", "Role", "State", "Last sign-in", "Actions"], members.map(row));
          } catch (error) {
            if (!quiet(view, error)) failed($("#tm-list", root), error, load);
          }
        }
        const status = () => $("#tm-status", root);
        const update = (id, body, button, said) =>
          act(view, status(), button, () => send(view, "/api/users/" + id, "PATCH", body), () => { load(); return said; });

        view.on(root, "change", (event) => {
          const select = event.target.closest("[data-role]");
          if (select) update(whole(select.dataset.role), { role: select.value }, select, "Role changed.");
        });
        view.on(root, "click", (event) => {
          const toggle = event.target.closest("[data-toggle]");
          if (toggle) {
            const disable = !toggle.dataset.disabled;
            update(whole(toggle.dataset.toggle), { disabled: disable }, toggle, disable ? "Disabled: their sessions ended." : "Enabled.");
            return;
          }
          const reset = event.target.closest("[data-reset]");
          if (reset) {
            const line = $('[data-reset-row="' + whole(reset.dataset.reset) + '"]', root);
            line.hidden = !line.hidden;
            if (!line.hidden) $("input", line).focus();
            return;
          }
          const remove = event.target.closest("[data-remove]");
          if (remove) {
            /* two steps, no dialog: the second press is the confirmation */
            if (remove.dataset.armed !== "1") {
              remove.dataset.armed = "1";
              remove.textContent = "Press again to remove";
              return;
            }
            act(view, status(), remove, () => send(view, "/api/users/" + whole(remove.dataset.remove), "DELETE"),
              () => { load(); return "Removed. Their cases and audit records stay."; });
          }
        });
        view.on(root, "submit", (event) => {
          event.preventDefault();
          const form = event.target;
          const submit = $("button[type=submit]", form);
          if (form.matches("[data-reset-form]")) {
            const password = form.elements.password.value;
            if (password.length < 12) { status().textContent = "The password needs at least 12 characters."; return; }
            update(whole(form.dataset.resetForm), { password }, submit, "Password set: they choose their own at the next sign-in.");
          } else if (form.id === "tm-add") {
            const values = fields(form);
            if (values.password.length < 12) { $("#tm-add-status", root).textContent = "The password needs at least 12 characters."; return; }
            act(view, $("#tm-add-status", root), submit, () => send(view, "/api/users", "POST", {
              username: values.username.toLowerCase(), display_name: values.display_name, role: values.role, password: values.password
            }), (made) => { form.reset(); load(); return "Added " + text(made && made.username) + ": they choose their own password when they first sign in."; });
          }
        });
        load();
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── API tokens */
  function tokens() {
    return {
      title: "API tokens",
      sub: "For scripts and integrations: scoped, expiring, revocable.",
      body: () => !isAdmin() ? adminOnly("manage API tokens") :
        '<section class="card panel" aria-labelledby="tk-new-h"><div class="panel-head"><h4 id="tk-new-h">New token</h4></div>' +
          '<form id="tk-new" class="sv-grid">' +
            field("tk-name", "Name", 'type="text" name="name" required maxlength="64" autocomplete="off" placeholder="splunk-forwarder"') +
            '<div class="sv-field"><label class="label-xs" for="tk-scope">Scope</label>' +
              '<select class="wb-field sv-select" id="tk-scope" name="scope" aria-describedby="tk-scope-hint">' +
                '<option value="read">read: every GET</option><option value="triage">triage: read, and run triages</option>' +
                '<option value="ingest">ingest: push alerts only</option></select>' +
              '<p class="wb-hint" id="tk-scope-hint">A SIEM that pushes alerts needs ingest and nothing more.</p></div>' +
            field("tk-days", "Expires after (days)", 'type="number" name="expires_in_days" min="1" max="730" inputmode="numeric" placeholder="never"') +
            '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Create token</button></div></form>' +
          '<div id="tk-once" hidden></div>' + statusLine("tk-new-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="tk-h"><div class="panel-head"><h4 id="tk-h">Tokens</h4></div>' +
          '<div id="tk-list">' + loading + "</div>" + statusLine("tk-status") + "</section>",
      mount(root, ctx) {
        if (!isAdmin()) return null;
        const view = life();
        const stateOf = (t) => (t.revoked_at ? "revoked" : t.expires_at && new Date(t.expires_at) < new Date() ? "expired" : "active");

        async function load() {
          try {
            const rows = objects(await get(view, "/api/tokens"));
            if (!view.alive) return;
            $("#tk-list", root).innerHTML = rows.length
              ? table(["Token", "Scope", "Created", "Last used", "State"], rows.map((t) => {
                  const state = stateOf(t);
                  return "<tr>" + cell("Token", esc(t.name) + '<span class="sv-sub">by ' + esc(t.created_by || "a removed member") + "</span>") +
                    cell("Scope", esc(t.scope)) + cell("Created", esc(when(t.created_at)), "mono") +
                    cell("Last used", esc(when(t.last_used_at)), "mono") +
                    cell("State", state === "active"
                      ? (t.expires_at ? "until " + esc(when(t.expires_at)) + " " : "") +
                        '<button type="button" class="btn btn-light btn-sm" data-revoke="' + whole(t.id) + '">Revoke</button>'
                      : esc(state)) + "</tr>";
                }))
              : emptyState("No tokens yet", "Create one above for each script or integration, so each can be revoked alone.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#tk-list", root), error, load);
          }
        }

        view.on(root, "submit", (event) => {
          event.preventDefault();
          const form = event.target;
          if (form.id !== "tk-new") return;
          const values = fields(form);
          const body = { name: values.name, scope: values.scope };
          if (values.expires_in_days) body.expires_in_days = whole(values.expires_in_days);
          act(view, $("#tk-new-status", root), $("button[type=submit]", form), () => send(view, "/api/tokens", "POST", body), (made) => {
            form.reset();
            const once = $("#tk-once", root);
            once.hidden = false;
            once.innerHTML = '<div class="sv-once" role="alert"><b>Copy it now: this is the only time it is shown.</b>' +
              '<div class="wb-row"><label class="sr-only" for="tk-value">The new token</label>' +
              '<input class="wb-field mono" id="tk-value" readonly autocomplete="off" spellcheck="false">' +
              '<button type="button" class="btn btn-dark btn-sm" data-copy-token>Copy</button>' +
              '<button type="button" class="btn btn-light btn-sm" data-hide-token>Done</button></div></div>';
            $("#tk-value", root).value = text(made && made.token);
            $("#tk-value", root).select();
            load();
            return "";
          });
        });
        view.on(root, "click", (event) => {
          if (event.target.closest("[data-copy-token]")) {
            const value = $("#tk-value", root).value;
            (navigator.clipboard ? navigator.clipboard.writeText(value) : Promise.reject(new Error("no clipboard")))
              .then(() => ctx.toast("Token copied"), () => { $("#tk-value", root).select(); ctx.toast("Select the token and copy it"); });
            return;
          }
          if (event.target.closest("[data-hide-token]")) {
            const once = $("#tk-once", root);
            once.innerHTML = "";
            once.hidden = true;
            return;
          }
          const revoke = event.target.closest("[data-revoke]");
          if (revoke) {
            if (revoke.dataset.armed !== "1") { revoke.dataset.armed = "1"; revoke.textContent = "Press again to revoke"; return; }
            act(view, $("#tk-status", root), revoke, () => send(view, "/api/tokens/" + whole(revoke.dataset.revoke), "DELETE"),
              () => { load(); return "Revoked: the token stops working now."; });
          }
        });
        load();
        return () => { view.end(); };
      }
    };
  }

  /* ─────────────────────────────────────────── Audit */
  function audit() {
    return {
      title: "Audit log",
      sub: "Who did what, in a chain that shows any edit.",
      body: () =>
        '<section class="card panel" aria-labelledby="au-h"><div class="panel-head"><h4 id="au-h">Records</h4>' +
          (isAdmin() ? '<button type="button" class="btn btn-light btn-sm" id="au-verify">Verify the chain</button>' : "") + "</div>" +
          (isAdmin() ? "" : '<p class="wb-hint">You see your own actions; an admin sees the whole workspace.</p>') +
          '<p class="wb-hint" id="au-verdict" role="status" aria-live="polite"></p>' +
          '<form id="au-filter" class="wb-row sv-filters" role="search">' +
            '<label class="sr-only" for="au-action">Action</label>' +
            '<input class="wb-field" id="au-action" name="action" maxlength="80" placeholder="An action, or its start: case." autocomplete="off">' +
            '<label class="sr-only" for="au-by">Who</label>' +
            '<input class="wb-field" id="au-by" name="by" maxlength="120" placeholder="Who: a username or token:name" autocomplete="off">' +
            '<label class="sr-only" for="au-since">Since</label><input class="wb-field sv-select" id="au-since" name="since" type="date">' +
            '<label class="sr-only" for="au-until">Until</label><input class="wb-field sv-select" id="au-until" name="until" type="date">' +
            '<button type="submit" class="btn btn-dark btn-sm">Filter</button></form>' +
          '<div id="au-list">' + loading + "</div>" +
          '<div class="wb-row" id="au-more-row" hidden><button type="button" class="btn btn-light btn-sm" id="au-more">Show more</button></div>' +
        "</section>",
      mount(root) {
        const view = life();
        const PAGE = 50;
        let offset = 0, rows = [];
        /* A record's detail, one line: what changed, not a JSON dump. */
        const detail = (d) => (d && typeof d === "object" ? Object.entries(d).slice(0, 6).map(([k, v]) =>
          k + ": " + (v && typeof v === "object" ? JSON.stringify(v).slice(0, 120) : text(v))).join(" · ") : "");

        async function load(more) {
          if (!more) { offset = 0; rows = []; }
          const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
          const values = fields($("#au-filter", root));
          if (values.action) params.set("action", values.action);
          if (values.by) params.set("by", values.by);
          if (values.since) params.set("since", values.since + "T00:00:00Z");
          if (values.until) {
            const end = new Date(values.until + "T00:00:00Z");
            if (!Number.isNaN(end.getTime())) params.set("until", new Date(end.getTime() + 86400000).toISOString());
          }
          try {
            const page = objects(await get(view, "/api/audit?" + params.toString()));
            if (!view.alive) return;
            rows = rows.concat(page);
            offset += page.length;
            $("#au-more-row", root).hidden = page.length < PAGE;
            $("#au-list", root).innerHTML = rows.length
              ? table(["Action", "Who", "Target", "Detail", "When"], rows.map((r) => "<tr>" +
                  cell("Action", '<span class="mono">' + esc(r.action) + "</span>") + cell("Who", esc(r.actor)) +
                  cell("Target", '<span class="mono">' + esc(text(r.target).slice(0, 80)) + "</span>") +
                  cell("Detail", esc(detail(r.detail))) + cell("When", esc(when(r.created_at)), "mono") + "</tr>"))
              : emptyState("No records match", "Try a shorter action, or no dates.");
          } catch (error) {
            if (!quiet(view, error)) failed($("#au-list", root), error, () => load(false));
          }
        }

        view.on($("#au-filter", root), "submit", (event) => { event.preventDefault(); load(false); });
        view.on($("#au-more", root), "click", () => load(true));
        const verify = $("#au-verify", root);
        if (verify) {
          view.on(verify, "click", () => act(view, $("#au-verdict", root), verify, () => get(view, "/api/audit/verify"), (a) => {
            const verdict = $("#au-verdict", root);
            verdict.classList.toggle("sv-bad", !(a && a.intact));
            if (a && a.intact) return "The chain holds: " + whole(a.records).toLocaleString() + " records, none edited, removed or reordered.";
            const where = objects(a && a.details).slice(0, 5).map((d) => "#" + whole(d.id) + " " + text(d.problem || d.reason || "")).join("; ");
            return whole(a && a.problems) + " record(s) break the chain" + (where ? ": " + where : "") +
              ". Restore the database from a backup, and keep this one for the investigation.";
          }));
        }
        load(false);
        return () => view.end();
      }
    };
  }

  /* ─────────────────────────────────────────── Profile */
  function profile() {
    return {
      title: "Your profile",
      sub: "Your name, your email and your password.",
      body: () =>
        '<section class="card panel" aria-labelledby="pf-h"><div class="panel-head"><h4 id="pf-h">You</h4></div>' +
          '<p class="wb-hint" id="pf-who"></p>' +
          '<form id="pf-form" class="sv-grid">' +
            field("pf-name", "Display name", 'type="text" name="display_name" maxlength="120" autocomplete="name"') +
            field("pf-email", "Email", 'type="email" name="email" maxlength="254" autocomplete="email"',
              "Used for password resets once the server sends email.") +
            '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Save</button></div></form>' +
          statusLine("pf-status") + "</section>" +
        '<section class="card panel sv-gap" aria-labelledby="pf-pw-h"><div class="panel-head"><h4 id="pf-pw-h">Password</h4></div>' +
          '<form id="pf-password" class="sv-grid">' +
            field("pf-current", "Current password", 'type="password" name="current_password" required maxlength="1024" autocomplete="current-password"') +
            field("pf-new", "New password", 'type="password" name="new_password" required minlength="12" maxlength="1024" autocomplete="new-password"',
              "At least 12 characters. Every other session of your account ends.") +
            '<div class="wb-row"><button type="submit" class="btn btn-dark btn-sm">Change password</button></div></form>' +
          statusLine("pf-pw-status") + "</section>",
      mount(root) {
        const view = life();
        async function load() {
          try {
            const me = await get(view, "/api/profile");
            if (!view.alive || !me) return;
            $("#pf-who", root).textContent = text(me.username) + " · " + (me.owner ? "owner" : text(me.role)) + " in " +
              text(me.workspace && me.workspace.name);
            $("#pf-name", root).value = text(me.display_name);
            $("#pf-email", root).value = text(me.email);
          } catch (error) {
            if (!quiet(view, error)) failed($("#pf-who", root), error, load);
          }
        }
        view.on(root, "submit", (event) => {
          event.preventDefault();
          const form = event.target;
          const submit = $("button[type=submit]", form);
          const values = fields(form);
          if (form.id === "pf-form") {
            act(view, $("#pf-status", root), submit,
              () => send(view, "/api/profile", "PATCH", { display_name: values.display_name, email: values.email || null }),
              () => {
                window.IntelPulseData.source.refresh().then(() => {
                  const who = document.getElementById("c-who");
                  const user = session().user;
                  if (who && user) who.textContent = user.displayName + " · " + (user.owner ? "owner" : user.role);
                }, () => {});
                return "Saved.";
              });
          } else if (form.id === "pf-password") {
            if (values.new_password.length < 12) { $("#pf-pw-status", root).textContent = "The new password needs at least 12 characters."; return; }
            act(view, $("#pf-pw-status", root), submit,
              () => send(view, "/api/profile", "PATCH", { current_password: values.current_password, new_password: values.new_password }),
              () => { form.reset(); return "Password changed. Every other session of your account has ended."; });
          }
        });
        load();
        return () => view.end();
      }
    };
  }

  Object.assign(views, {
    settings: () => settings(),
    team: () => team(),
    tokens: () => tokens(),
    audit: () => audit(),
    profile: () => profile()
  });

  /* Which of these a person sees in the sidebar: an admin all five, an analyst their own two. */
  window.IntelPulseWorkspacePanes = [
    { id: "settings", label: "Settings", admin: true },
    { id: "team", label: "Team", admin: true },
    { id: "tokens", label: "API tokens", admin: true },
    { id: "audit", label: "Audit log", admin: false },
    { id: "profile", label: "Profile", admin: false }
  ];
})();
