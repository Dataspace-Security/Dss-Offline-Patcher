/* DSS Patcher: apply the saved colour theme before the first paint (no flash).
   Loaded as a same-origin file because the server's CSP blocks inline scripts. */
(function () {
  var pref = "system";
  try { pref = localStorage.getItem("offpatch.theme") || "system"; } catch (e) { /* storage blocked */ }
  var dark = pref === "dark" ||
    (pref !== "light" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
})();
