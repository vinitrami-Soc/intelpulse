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
      "</form>" +
      (session && session.emailEnabled
        ? '<p class="wb-hint account-alt"><a class="wb-link" href="#/forgot" id="account-to-forgot">Forgot your password?</a></p>'
        : "") +
      (session && session.signupOpen
        ? '<p class="wb-hint account-alt">New here? <a class="wb-link" href="#/signup" id="account-to-signup">Create an account</a></p>'
        : "") +
      "</section>";
  }

  /* Sign-up, while the owner allows it: a workspace for one person, or for an organization. */
  function signUpView() {
    const choice = (value, title, detail, checked) =>
      '<label class="account-choice"><input type="radio" name="kind" value="' + value + '"' + (checked ? " checked" : "") + ">" +
        "<span><b>" + title + "</b><small>" + detail + "</small></span></label>";
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Create an account</h1>' +
      '<p class="wb-hint account-lead">Your own workspace on this server: its cases, keys and settings are yours alone.</p>' +
      '<form id="account-form" novalidate>' +
        '<fieldset class="account-kind"><legend class="label-xs">Who is it for</legend>' +
          choice("individual", "Just me", "One person, one workspace.", true) +
          choice("organization", "My organization", "A team: you are its admin and add the others.", false) +
        "</fieldset>" +
        '<div id="account-org-field" hidden>' +
          field("account-organization", "Organization",
            'type="text" name="organization" autocomplete="organization" maxlength="120"') + "</div>" +
        field("account-name", "Your name", 'type="text" name="display_name" autocomplete="name" maxlength="120"') +
        field("account-username", "Username",
          'type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64"',
          "3 to 64 lowercase letters, digits, dots, dashes or underscores.") +
        field("account-password", "Password",
          'type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="1024"',
          "At least 12 characters.") +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Create account</button></div>' +
      "</form>" +
      '<p class="wb-hint account-alt">Have an account? <a class="wb-link" href="#/signin">Sign in</a></p>' +
      "</section>";
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

  function passwordView() {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Choose your own password</h1>' +
      '<p class="wb-hint account-lead">An admin set the password you signed in with. Choose one only you know ' +
        "before you go on; every other session of your account ends.</p>" +
      '<form id="account-form" novalidate>' +
        field("account-current", "The password you were given",
          'type="password" name="current" autocomplete="current-password" required maxlength="1024"') +
        field("account-password", "New password",
          'type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="1024"',
          "At least 12 characters.") +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Save and continue</button></div>' +
      "</form></section>";
  }

  /* An invitation's own page: whose workspace it opens and as what, then the person's account. */
  function joinView(invite) {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Join ' + esc(invite.workspace) + "</h1>" +
      '<p class="wb-hint account-lead">You were invited as ' + (invite.role === "admin" ? "an admin" : "an analyst") +
        ". Choose your username and password: the link then stops working.</p>" +
      '<form id="account-form" novalidate>' +
        field("account-name", "Your name", 'type="text" name="display_name" autocomplete="name" maxlength="120"') +
        field("account-username", "Username",
          'type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64"',
          "3 to 64 lowercase letters, digits, dots, dashes or underscores.") +
        field("account-password", "Password",
          'type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="1024"',
          "At least 12 characters.") +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Join</button></div>' +
      "</form></section>";
  }

  function invalidInvite(message) {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">This invitation does not work</h1>' +
      '<p class="wb-hint account-lead" role="alert">' + esc(message) + "</p>" +
      '<p class="wb-hint account-alt"><a class="wb-link" href="#/signin">Sign in</a> if you have an account.</p></section>';
  }

  /* The token a link carries: #/join/<token>, #/reset/<token>, #/confirm/<token>. */
  const linkToken = (kind) => {
    const match = new RegExp("^#/" + kind + "/([A-Za-z0-9_-]{20,200})$").exec(location.hash);
    return match ? match[1] : "";
  };
  const inviteToken = () => linkToken("join");

  function messageView(title, message, href, label) {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">' + esc(title) + "</h1>" +
      '<p class="wb-hint account-lead" role="status" id="account-message">' + esc(message) + "</p>" +
      '<p class="account-alt"><a class="btn btn-dark" href="' + href + '">' + esc(label) + "</a></p></section>";
  }

  function forgotView() {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Reset your password</h1>' +
      '<p class="wb-hint account-lead">Give your username or your confirmed address. If an account matches, a link ' +
        "that works once, for one hour, is sent to its address.</p>" +
      '<form id="account-form" novalidate>' +
        field("account-login", "Username or email",
          'type="text" name="login" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="254"') +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Send the link</button></div>' +
      "</form>" +
      '<p class="wb-hint account-alt"><a class="wb-link" href="#/signin">Back to sign-in</a></p></section>';
  }

  function resetView() {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Choose a new password</h1>' +
      '<p class="wb-hint account-lead">Every session of your account ends when it changes.</p>' +
      '<form id="account-form" novalidate>' +
        field("account-password", "New password",
          'type="password" name="password" autocomplete="new-password" required minlength="12" maxlength="1024"',
          "At least 12 characters.") +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Set the password</button></div>' +
      "</form></section>";
  }

  /* A button, not the link itself: a mail scanner that opens links confirms nothing. */
  function confirmView() {
    return '<section class="card panel account-card" aria-labelledby="account-title">' +
      '<h1 class="account-title" id="account-title">Confirm your address</h1>' +
      '<p class="wb-hint account-lead">Press the button to confirm that the address this link was sent to is yours.</p>' +
      '<form id="account-form" novalidate>' +
        '<p class="wb-error" id="account-error" role="alert" hidden></p>' +
        '<div class="wb-row account-actions"><button type="submit" class="btn btn-dark" id="account-submit">Confirm my address</button></div>' +
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
    if (view === "password" && error.status === 403) return "The password you were given is not right.";
    if (view === "signup" && error.status === 403) return "Sign-up is closed on this server. Ask its owner for an invitation.";
    if (view === "join" && error.status === 404) return "This invitation stopped working: it may have been used or revoked. Ask for a new one.";
    if ((view === "reset" || view === "confirm") && error.status === 404) {
      return "This link stopped working: it may have been used already or have expired. Ask for a new one.";
    }
    if (view === "forgot" && error.status === 409) return "This server does not send email. Ask an admin to set a new password for you.";
    if (view === "signup" && error.status === 409) return "This server is not set up yet.";
    if (view === "signup" && error.status === 429) return error.message.charAt(0).toUpperCase() + error.message.slice(1) + ".";
    if (error.status === 422) return error.message;
    return error.message || "That did not work. Try again.";
  }

  async function render(view, root, done) {
    const data = window.IntelPulseData;
    let invite = null;
    if (view === "join") {
      const token = inviteToken();
      root.innerHTML = '<section class="card panel account-card"><p class="wb-hint" role="status">Opening the invitation…</p></section>';
      try {
        invite = token ? await data.source.checkInvite(token) : null;
      } catch (error) {
        root.innerHTML = invalidInvite(error && error.status === 404 ? "It may have been used, revoked or expired. Ask for a new one."
          : error && error.status === 429 ? error.message : "The server could not be reached. Try again.");
        return;
      }
      if (!invite) { root.innerHTML = invalidInvite("The link is not whole. Open it again from the message you were sent."); return; }
      invite.token = token;
    }
    root.innerHTML = view === "setup" ? setUpView() : view === "password" ? passwordView()
      : view === "signup" ? signUpView() : view === "join" ? joinView(invite)
      : view === "forgot" ? forgotView() : view === "reset" ? resetView() : view === "confirm" ? confirmView()
      : signInView(data && data.session);
    const form = $("#account-form", root), submit = $("#account-submit", root);
    if (view === "signup") {
      /* the organization's name is asked for, and required, only for an organization */
      const org = $("#account-org-field", root), name = $("#account-organization", root);
      form.addEventListener("change", (event) => {
        if (event.target.name !== "kind") return;
        const team = event.target.value === "organization";
        org.hidden = !team;
        name.required = team;
        if (team) name.focus();
      });
    }
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
      if (view !== "signin" && view !== "forgot" && view !== "confirm" && String(values.password).length < 12) {
        showError(root, "The password needs at least 12 characters.", "account-password");
        return;
      }
      submit.disabled = true;
      submit.setAttribute("aria-busy", "true");
      showError(root, "");
      try {
        if (view === "password") {
          await data.source.changePassword(values.current, values.password);
        } else if (view === "forgot") {
          const said = await data.source.forgot(String(values.login || "").trim());
          root.innerHTML = messageView("Check your email", said ? said.charAt(0).toUpperCase() + said.slice(1) + "." : "",
            "#/signin", "Back to sign-in");
          return;
        } else if (view === "reset" || view === "confirm") {
          const token = linkToken(view);
          if (!token) throw new Error("The link is not whole. Open it again from the message you were sent.");
          if (view === "reset") {
            await data.source.resetPassword(token, values.password);
            root.innerHTML = messageView("Password changed",
              "Sign in with your new password. Every session of your account has ended.", "#/signin", "Sign in");
          } else {
            const address = await data.source.confirmEmail(token);
            const signedIn = Boolean(data.session && data.session.user);
            root.innerHTML = messageView("Address confirmed", (address || "Your address") + " is confirmed.",
              signedIn ? "#/console/dashboard" : "#/signin", signedIn ? "Open the console" : "Sign in");
          }
          return;
        } else if (view === "join") {
          await data.source.join({
            token: invite.token, display_name: String(values.display_name || "").trim(),
            username: values.username.trim().toLowerCase(), password: values.password
          });
        } else if (view === "signup") {
          await data.source.signUp({
            kind: values.kind === "organization" ? "organization" : "individual",
            organization: values.kind === "organization" ? String(values.organization || "").trim() : "",
            display_name: String(values.display_name || "").trim(),
            username: values.username.trim().toLowerCase(), password: values.password
          });
        } else if (view === "setup") {
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
        if (password && (view === "signin" || view === "password")) password.value = "";
        showError(root, explain(error, view), error && error.status === 401 ? "account-password" : null);
      } finally {
        submit.disabled = false;
        submit.removeAttribute("aria-busy");
      }
    });
  }

  window.IntelPulseAccount = { render, remember };
})();
