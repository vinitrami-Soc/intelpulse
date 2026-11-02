/* IntelPulse · getting into a server: setting it up the first time, signing in.
 *
 * Only in server mode (see data.js). The views are plain forms: every value a
 * person types goes to the server as JSON over fetch, nothing is stored in the
 * browser, and every message the server sends back is shown as text.
 */
(function () {
  "use strict";

  const $ = (sel, scope) => (scope || document).querySelector(sel);
  const esc = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  /* Where to go after signing in: the console page that sent the person here. */
  let returnTo = "#/console/dashboard";
  function remember(hash) {
    if (typeof hash === "string" && /^#\/console\/[a-z-]+$/.test(hash)) returnTo = hash;
  }

  function field(id, label, attrs, hint) {
    return '<div class="account-field">' +
      '<label class="label-xs" for="' + id + '">' + label + "</label>" +
      '<input id="' + id + '" class="wb-field" ' + attrs +
        (hint ? ' aria-describedby="' + id + '-hint"' : "") + ">" +
      (hint ? '<p class="wb-hint" id="' + id + '-hint">' + hint + "</p>" : "") +
      "</div>";
  }

  function signInView(session) {
    const workspace = session && session.workspace ? session.workspace.name : "";
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Sign in to IntelPulse</h1>' +
      '<p class="wb-hint account-lead">' + (workspace ? esc(workspace) + " · " : "") +
        "this server's triage console. Scripts use API tokens instead.</p>" +
      '<form id="account-form" novalidate>' +
        field("account-username", "Username",
          'type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64"') +
        field("account-password", "Password",
          'type="password" name="password" autocomplete="current-password" required maxlength="1024"') +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Sign in</button></div>' +
      "</form></section>";
  }

  function setUpView() {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Set up this server</h1>' +
      '<p class="wb-hint account-lead">No one has an account yet. The first is the owner\'s: the admin of the ' +
        "organization every existing case belongs to. Get the one-time code on the server with " +
        "<code>python -m app.cli setup-code</code> (in Docker: <code>docker compose exec api python -m app.cli setup-code</code>).</p>" +
      '<form id="account-form" novalidate>' +
        field("account-code", "Setup code",
          'type="text" name="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" required maxlength="64"',
          "It works once. It is never written to the server's log.") +
        field("account-organization", "Organization",
          'type="text" name="organization" autocomplete="organization" required maxlength="120"') +
        field("account-username", "Username",
          'type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64"',
          "3 to 64 lowercase letters, digits, dots, dashes or underscores.") +
        field("account-password", "Password",
          'type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="1024"',
          "At least 12 characters.") +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Set up and sign in</button></div>' +
      "</form></section>";
  }

  function showError(root, message, focusId) {
    const box = $("#account-error", root);
    box.textContent = message;
    box.hidden = !message;
    root.querySelectorAll("input").forEach((input) => input.removeAttribute("aria-invalid"));
    if (focusId) {
      const input = $("#" + focusId, root);
      if (input) { input.setAttribute("aria-invalid", "true"); input.focus(); }
    }
  }

  /* What a refusal means to the person at the form, in their words. */
  function explain(error, view) {
    if (!error || typeof error.status !== "number") return "The server could not be reached. Try again.";
    if (error.status === 401) return "Wrong username or password.";
    if (error.status === 429) return error.message;
    if (view === "setup" && error.status === 403) return "That setup code is not right.";
    if (view === "setup" && error.status === 409) return "This server is set up already: sign in instead.";
    if (error.status === 422) return error.message;
    return error.message || "That did not work. Try again.";
  }

  function render(view, root, done) {
    const data = window.IntelPulseData;
    root.innerHTML = view === "setup" ? setUpView() : signInView(data && data.session);
    const form = $("#account-form", root), submit = $("#account-submit", root);
    const first = $("input", form);
    if (first) first.focus({ preventScroll: true });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = Object.fromEntries(new FormData(form).entries());
      for (const input of form.querySelectorAll("input[required]")) {
        if (!String(values[input.name] || "").trim()) {
          showError(root, input.labels[0].textContent + " is required.", input.id);
          return;
        }
      }
      if (view === "setup" && String(values.password).length < 12) {
        showError(root, "The password needs at least 12 characters.", "account-password");
        return;
      }
      submit.disabled = true;
      submit.setAttribute("aria-busy", "true");
      showError(root, "");
      try {
        if (view === "setup") {
          await data.source.setUp({
            code: values.code.trim(), organization: values.organization.trim(),
            username: values.username.trim().toLowerCase(), password: values.password
          });
        } else {
          await data.source.signIn(values.username.trim().toLowerCase(), values.password);
        }
        const target = returnTo;
        returnTo = "#/console/dashboard";
        done(target);
      } catch (error) {
        const password = $("#account-password", root);
        if (password && view !== "setup") password.value = "";
        showError(root, explain(error, view), error && error.status === 401 ? "account-password" : null);
      } finally {
        submit.disabled = false;
        submit.removeAttribute("aria-busy");
      }
    });
  }

  window.IntelPulseAccount = { render, remember };
})();
