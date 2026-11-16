// Runs synchronously in <head> (app.js is deferred) so the theme is set before
// first paint. A file rather than inline <script>, because the CSP carries no
// 'unsafe-inline'.
(function () {
  var root = document.documentElement;
  // Before first paint: the no-JS `:target` rules are scoped to
  // `html:not(.js)`, and must not fight the `is-current` class app.js drives.
  root.classList.add("js");
  var t =
    localStorage.getItem("comics-theme") ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  root.setAttribute("data-theme", t);
})();
