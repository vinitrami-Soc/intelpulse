/* The product, privacy and help pages: plain documents that need no other script.
 * This sets the theme the visitor chose on the site (suite.js keeps it under
 * "ip:theme"), before the page paints, so a dark-theme reader is not flashed
 * white. Storage can be off (a private window): then the light theme stays.
 */
(function () {
  "use strict";
  let mode = "light";
  try { mode = JSON.parse(localStorage.getItem("ip:theme")) === "dark" ? "dark" : "light"; } catch (_) { /* no storage */ }
  document.documentElement.setAttribute("data-theme", mode);
})();
