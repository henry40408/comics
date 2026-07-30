// Sets the theme before first paint, so the reader never sees a flash of the
// wrong palette. Kept out of app.js because that one is `defer`red — this has
// to run synchronously in <head>, before the body is styled.
//
// It is a separate file rather than an inline <script> so the Content-Security-
// Policy can stay at `script-src 'self'`: allowing this one snippet inline would
// mean `'unsafe-inline'`, which allows every injected snippet too.
(function () {
  var t =
    localStorage.getItem("comics-theme") ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", t);
})();
