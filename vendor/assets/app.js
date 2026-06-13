// Comics — shared front-end behaviour for the library and reader pages.
// Loaded with `defer`, so the DOM is ready when this runs. The pre-paint
// theme is set by a tiny inline snippet in each template's <head>.
(function () {
  "use strict";

  var root = document.documentElement;

  // ---- theme toggle (persists a manual choice, otherwise follows the system) ----
  var sys = matchMedia("(prefers-color-scheme: dark)");
  sys.addEventListener("change", function (e) {
    if (!localStorage.getItem("comics-theme")) {
      root.setAttribute("data-theme", e.matches ? "dark" : "light");
    }
  });
  var themeBtn = document.getElementById("theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      localStorage.setItem("comics-theme", next);
      root.setAttribute("data-theme", next);
    });
  }

  // ---- library: render server-side timestamps in the viewer's locale ----
  if (window.customElements && !customElements.get("x-time")) {
    class TimeComponent extends HTMLTimeElement {
      connectedCallback() {
        const d = new Date(this.getAttribute("datetime"));
        this.innerHTML = new Intl.DateTimeFormat(undefined, {
          dateStyle: "medium",
          timeStyle: "medium",
        }).format(d);
      }
    }
    customElements.define("x-time", TimeComponent, { extends: "time" });
  }

  // ---- reader ----
  if (!document.body.classList.contains("reader")) return;

  const body = document.body;
  const pagesEl = document.getElementById("pages");
  const pgs = [...pagesEl.querySelectorAll(".pg")];
  const TOTAL = pgs.length;
  if (!TOTAL) return;

  const bar = document.getElementById("bar");
  const curEls = [document.getElementById("cur"), document.getElementById("cur2")];
  const thumbsBox = document.getElementById("thumbs");
  const thumbBtns = [...thumbsBox.querySelectorAll("button")];
  let current = 1;

  const centerThumb = () => {
    const b = thumbBtns[current - 1];
    if (b) thumbsBox.scrollTo({ left: b.offsetLeft - thumbsBox.clientWidth / 2 + b.offsetWidth / 2, behavior: "smooth" });
  };
  const updateUI = () => {
    curEls.forEach((e) => (e.textContent = current));
    bar.style.width = (current / TOTAL) * 100 + "%";
    thumbBtns.forEach((b, i) => b.classList.toggle("on", i + 1 === current));
    centerThumb();
  };
  const paintPage = () => pgs.forEach((p, i) => p.classList.toggle("is-current", i + 1 === current));
  const setCurrent = (n) => { current = Math.min(TOTAL, Math.max(1, n)); paintPage(); updateUI(); };

  // RTL paged nav: left = next. pointerup + dedupe avoids ghost-click double fire.
  let lastTap = 0;
  const tapNav = (d) => { const now = Date.now(); if (now - lastTap < 90) return; lastTap = now; setCurrent(current + d); };
  document.getElementById("next").addEventListener("pointerup", (e) => { e.preventDefault(); tapNav(1); });
  document.getElementById("prev").addEventListener("pointerup", (e) => { e.preventDefault(); tapNav(-1); });
  document.addEventListener("keydown", (e) => {
    if (body.dataset.mode !== "paged") return;
    if (e.key === "ArrowLeft") setCurrent(current + 1);
    if (e.key === "ArrowRight") setCurrent(current - 1);
  });

  // thumbnails jump (both modes)
  thumbBtns.forEach((b, i) => b.addEventListener("click", () => {
    if (body.dataset.mode === "scroll") pgs[i].scrollIntoView({ behavior: "smooth", block: "start" });
    else setCurrent(i + 1);
  }));

  // scroll mode: track the most-visible page
  const ratios = new Array(TOTAL).fill(0);
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((en) => { ratios[pgs.indexOf(en.target)] = en.isIntersecting ? en.intersectionRatio : 0; });
      if (body.dataset.mode !== "scroll") return;
      let bi = 0, bv = -1;
      for (let i = 0; i < TOTAL; i++) if (ratios[i] > bv) { bv = ratios[i]; bi = i; }
      if (bv > 0) { current = bi + 1; updateUI(); }
    },
    { root: pagesEl, threshold: [0, 0.25, 0.5, 0.75, 1] }
  );
  pgs.forEach((p) => io.observe(p));

  // mode switch
  document.getElementById("seg").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    body.dataset.mode = b.dataset.m;
    [...e.currentTarget.children].forEach((x) => x.classList.toggle("on", x === b));
    if (b.dataset.m === "paged") { paintPage(); updateUI(); }
    else pgs[current - 1].scrollIntoView({ block: "start" });
  });

  setCurrent(1);

  // first visit: flash the left/right arrows once as a hint
  if (!localStorage.getItem("comics-reader-hinted")) {
    body.classList.add("hint");
    localStorage.setItem("comics-reader-hinted", "1");
    setTimeout(() => body.classList.remove("hint"), 2000);
  }
})();
