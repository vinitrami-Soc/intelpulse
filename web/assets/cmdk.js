/* Command palette (⌘K / Ctrl-K).
 *
 * Once a tool has more than a handful of actions, a menu stops scaling and an
 * analyst stops hunting: they type what they want. This is the same contract
 * users already know from Linear, Raycast and GitHub — fuzzy subsequence match,
 * arrow keys, Enter, Escape — implemented in ~180 lines with no dependency.
 *
 * Accessibility is part of the contract, not a coat of paint: the dialog traps
 * focus, announces itself, and every action is reachable by keyboard alone.
 */
(function (root, factory) {
  const api = factory();
  root.IntelPulseCmdK = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const esc = (value) => String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  /**
   * Subsequence match with a score.
   * Consecutive characters and word starts score higher, so "rt" finds
   * "Run triage" above "Report — ticket".
   */
  function fuzzy(query, text) {
    if (!query) return { score: 0.1, ranges: [] };
    const haystack = text.toLowerCase();
    const needle = query.toLowerCase();
    let score = 0;
    let index = 0;
    let previous = -2;
    const ranges = [];

    for (const char of needle) {
      if (char === " ") continue;
      const found = haystack.indexOf(char, index);
      if (found === -1) return null;
      if (found === previous + 1) score += 3;                       // consecutive
      if (found === 0 || /[\s\-_/]/.test(haystack[found - 1])) score += 4;  // word start
      score += 1;
      ranges.push(found);
      previous = found;
      index = found + 1;
    }
    score -= (haystack.length - needle.length) * 0.02;              // prefer tight matches
    return { score, ranges };
  }

  function highlight(text, ranges) {
    if (!ranges || !ranges.length) return esc(text);
    const set = new Set(ranges);
    return Array.from(text)
      .map((char, i) => (set.has(i) ? "<mark>" + esc(char) + "</mark>" : esc(char)))
      .join("");
  }

  const ICONS = {
    play: '<path d="M6 4l12 8-12 8Z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="M16.5 16.5 21 21"/>',
    doc: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/><path d="M14 3v5h5"/>',
    graph: '<circle cx="5" cy="6" r="2.2"/><circle cx="19" cy="9" r="2.2"/><circle cx="9" cy="18" r="2.2"/><path d="M7.1 7.2 16.9 8.4M6.4 8.1l2 7.6M10.9 16.6l6.5-5.6"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.5l3.5 2"/>',
    theme: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>',
    download: '<path d="M12 4v11M8 11l4 4 4-4M5 19h14"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    shield: '<path d="M12 3 20 6v6c0 4.5-3.2 7.9-8 9-4.8-1.1-8-4.5-8-9V6Z"/>',
    keyboard: '<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M7 10h.01M11 10h.01M15 10h.01M7 14h10"/>',
    file: '<path d="M13 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9Z"/><path d="M13 3v6h6"/>',
    trash: '<path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>'
  };

  const state = {
    commands: [],
    filtered: [],
    active: 0,
    open: false,
    lastFocus: null,
    onRun: null,
    recents: []
  };

  let els = {};

  function render() {
    const query = els.input.value.trim();
    const scored = [];

    state.commands.forEach((command) => {
      if (command.when && !command.when()) return;
      const haystack = command.label + " " + (command.group || "") + " " + (command.keywords || "");
      const match = fuzzy(query, haystack);
      if (!match) return;
      const recency = state.recents.indexOf(command.id);
      const bonus = recency === -1 ? 0 : (state.recents.length - recency) * 1.2;
      scored.push({ command, score: match.score + bonus, ranges: fuzzy(query, command.label)?.ranges || [] });
    });

    scored.sort((a, b) => b.score - a.score);
    state.filtered = scored.slice(0, 40);
    state.active = 0;

    if (!state.filtered.length) {
      els.list.innerHTML =
        '<div class="empty" style="padding:28px 12px"><b>No matching command</b>Try “triage”, “theme”, “ticket” or “shortcuts”.</div>';
      return;
    }

    let html = "";
    let group = null;
    state.filtered.forEach((entry, index) => {
      if (entry.command.group !== group) {
        group = entry.command.group;
        html += '<div class="cmdk-group">' + esc(group) + "</div>";
      }
      html +=
        '<button class="cmdk-item" type="button" role="option" id="cmdk-opt-' + index + '"' +
        ' aria-selected="' + (index === state.active) + '" data-index="' + index + '">' +
          '<svg viewBox="0 0 24 24">' + (ICONS[entry.command.icon] || ICONS.play) + "</svg>" +
          "<span>" + highlight(entry.command.label, entry.ranges) + "</span>" +
          (entry.command.hint ? '<span class="cmdk-hint">' + esc(entry.command.hint) + "</span>" : "") +
        "</button>";
    });
    els.list.innerHTML = html;
    syncActive();
  }

  function syncActive() {
    const items = els.list.querySelectorAll(".cmdk-item");
    items.forEach((item, index) => item.setAttribute("aria-selected", String(index === state.active)));
    const current = items[state.active];
    if (current) {
      current.scrollIntoView({ block: "nearest" });
      els.input.setAttribute("aria-activedescendant", current.id);
    }
  }

  function move(delta) {
    if (!state.filtered.length) return;
    state.active = (state.active + delta + state.filtered.length) % state.filtered.length;
    syncActive();
  }

  function run(index) {
    const entry = state.filtered[index];
    if (!entry) return;
    state.recents = [entry.command.id].concat(state.recents.filter((id) => id !== entry.command.id)).slice(0, 6);
    try { localStorage.setItem("intelpulse:cmdk-recents", JSON.stringify(state.recents)); } catch (_) { /* private mode */ }
    close();
    // Let the dialog finish closing before the action moves the page.
    requestAnimationFrame(() => entry.command.run());
  }

  function open() {
    if (state.open) return;
    state.open = true;
    state.lastFocus = document.activeElement;
    els.scrim.hidden = false;
    els.input.value = "";
    render();
    els.input.focus();
  }

  function close() {
    if (!state.open) return;
    state.open = false;
    els.scrim.hidden = true;
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
  }

  function onKeydown(event) {
    if (!state.open) return;
    if (event.key === "Escape") { event.preventDefault(); close(); return; }
    if (event.key === "ArrowDown") { event.preventDefault(); move(1); return; }
    if (event.key === "ArrowUp") { event.preventDefault(); move(-1); return; }
    if (event.key === "Home") { event.preventDefault(); state.active = 0; syncActive(); return; }
    if (event.key === "End") { event.preventDefault(); state.active = state.filtered.length - 1; syncActive(); return; }
    if (event.key === "Enter") { event.preventDefault(); run(state.active); return; }
    if (event.key === "Tab") { event.preventDefault(); move(event.shiftKey ? -1 : 1); }
  }

  function mount(options) {
    state.commands = options.commands || [];
    try {
      state.recents = JSON.parse(localStorage.getItem("intelpulse:cmdk-recents") || "[]");
    } catch (_) { state.recents = []; }

    const host = document.createElement("div");
    host.className = "scrim";
    host.hidden = true;
    host.innerHTML =
      '<div class="cmdk" role="dialog" aria-modal="true" aria-label="Command palette">' +
        '<div class="cmdk-input">' +
          '<svg viewBox="0 0 24 24">' + ICONS.search + "</svg>" +
          '<input type="text" role="combobox" aria-expanded="true" aria-controls="cmdk-list"' +
          ' aria-autocomplete="list" placeholder="Type a command or search…" spellcheck="false">' +
          "<kbd>esc</kbd>" +
        "</div>" +
        '<div class="cmdk-list" id="cmdk-list" role="listbox" aria-label="Commands"></div>' +
        '<div class="cmdk-foot">' +
          "<span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>" +
          "<span><kbd>↵</kbd> run</span>" +
          "<span><kbd>esc</kbd> close</span>" +
        "</div>" +
      "</div>";
    document.body.appendChild(host);

    els = {
      scrim: host,
      input: host.querySelector("input"),
      list: host.querySelector(".cmdk-list")
    };

    els.input.addEventListener("input", render);
    els.list.addEventListener("click", (event) => {
      const item = event.target.closest(".cmdk-item");
      if (item) run(Number(item.dataset.index));
    });
    els.list.addEventListener("mousemove", (event) => {
      const item = event.target.closest(".cmdk-item");
      if (item && Number(item.dataset.index) !== state.active) {
        state.active = Number(item.dataset.index);
        syncActive();
      }
    });
    host.addEventListener("mousedown", (event) => { if (event.target === host) close(); });
    document.addEventListener("keydown", onKeydown, true);
  }

  return {
    mount,
    open,
    close,
    toggle: () => (state.open ? close() : open()),
    isOpen: () => state.open,
    fuzzy,
    ICONS
  };
});
