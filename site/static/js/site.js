// AttackTree site: theme toggle, menus, copy buttons, table-of-contents tracking, and search. No dependencies.
(() => {
  "use strict";
  const root = document.documentElement;

  // ---- theme ---------------------------------------------------------------
  const setTheme = (theme) => {
    root.dataset.theme = theme;
    const light = document.getElementById("hl-light");
    const dark = document.getElementById("hl-dark");
    if (light) light.media = theme === "light" ? "all" : "not all";
    if (dark) dark.media = theme === "dark" ? "all" : "not all";
    try { localStorage.setItem("theme", theme); } catch (e) { /* storage unavailable */ }
  };
  const currentTheme = () => root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.querySelectorAll("[data-theme-toggle]").forEach((btn) =>
    btn.addEventListener("click", () => setTheme(currentTheme() === "dark" ? "light" : "dark")));

  // ---- menus ---------------------------------------------------------------
  const wireToggle = (selector, targetId) => {
    const btn = document.querySelector(selector);
    const target = document.getElementById(targetId);
    if (!btn || !target) return;
    btn.addEventListener("click", () => {
      const open = target.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
    });
  };
  wireToggle("[data-nav-toggle]", "site-nav-list");
  wireToggle("[data-docs-nav-toggle]", "docs-nav");

  // ---- copy buttons --------------------------------------------------------
  const copy = async (text, btn) => {
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; }
    catch (e) { btn.textContent = "Press ⌘C"; }
    setTimeout(() => { btn.textContent = "Copy"; }, 1600);
  };
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    const code = btn.closest("[data-copy-root]")?.querySelector("code");
    if (code) btn.addEventListener("click", () => copy(code.innerText.trim(), btn));
  });
  document.querySelectorAll(".prose pre").forEach((pre) => {
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "copy-btn"; btn.textContent = "Copy";
    btn.setAttribute("aria-label", "Copy code");
    btn.addEventListener("click", () => copy(pre.querySelector("code")?.innerText ?? pre.innerText, btn));
    pre.appendChild(btn);
  });

  // ---- table of contents ---------------------------------------------------
  const tocLinks = [...document.querySelectorAll(".docs-toc a")];
  if (tocLinks.length && "IntersectionObserver" in window) {
    const byId = new Map(tocLinks.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        tocLinks.forEach((a) => a.classList.remove("active"));
        byId.get(entry.target.id)?.classList.add("active");
      });
    }, { rootMargin: "-80px 0px -70% 0px" });
    byId.forEach((_, id) => { const el = document.getElementById(id); if (el) observer.observe(el); });
  }

  // ---- search --------------------------------------------------------------
  const dialog = document.getElementById("search-dialog");
  const input = document.getElementById("search-input");
  const list = document.getElementById("search-results");
  if (!dialog || !input || !list) return;
  let index = null;
  let selected = -1;

  const loadIndex = async () => {
    if (index) return index;
    const res = await fetch(input.dataset.index);
    const docs = await res.json();
    index = docs.map((d) => ({ ...d, _t: (d.title || "").toLowerCase(), _d: (d.description || "").toLowerCase(), _b: (d.body || "").toLowerCase() }));
    return index;
  };
  const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const highlight = (text, terms) => {
    let out = escapeHtml(text);
    terms.forEach((t) => { if (t.length > 1) out = out.replace(new RegExp(`(${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"), "<mark>$1</mark>"); });
    return out;
  };
  const excerpt = (doc, terms) => {
    const at = terms.map((t) => doc._b.indexOf(t)).filter((i) => i >= 0).sort((a, b) => a - b)[0];
    if (at === undefined) return doc.description || "";
    const start = Math.max(0, at - 60);
    return (start > 0 ? "…" : "") + doc.body.slice(start, start + 160).replace(/\s+/g, " ") + "…";
  };
  const render = async () => {
    const q = input.value.trim().toLowerCase();
    selected = -1;
    if (!q) { list.innerHTML = ""; return; }
    const docs = await loadIndex();
    const terms = q.split(/\s+/).filter(Boolean);
    const scored = docs.map((d) => {
      let score = 0;
      for (const t of terms) {
        const inT = d._t.includes(t), inD = d._d.includes(t), inB = d._b.includes(t);
        if (!inT && !inD && !inB) return null;
        score += (inT ? 12 : 0) + (inD ? 5 : 0) + (inB ? 1 + Math.min(4, d._b.split(t).length - 1) * 0.5 : 0);
      }
      if (d._t.startsWith(q)) score += 10;
      return { d, score };
    }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 12);
    list.innerHTML = scored.length
      ? scored.map(({ d }) => `<li><a href="${d.url}"><strong>${highlight(d.title || d.url, terms)}</strong><span>${highlight(excerpt(d, terms), terms)}</span></a></li>`).join("")
      : `<li class="search-empty">No results for “${escapeHtml(input.value)}”.</li>`;
  };
  const open = () => { dialog.showModal(); input.focus(); input.select(); loadIndex().catch(() => {}); };
  document.querySelectorAll("[data-search-open]").forEach((b) => b.addEventListener("click", open));
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if ((e.key === "/" && !typing) || (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey))) { e.preventDefault(); if (!dialog.open) open(); }
  });
  input.addEventListener("input", () => { render().catch(() => { list.innerHTML = '<li class="search-empty">Search is unavailable offline.</li>'; }); });
  input.addEventListener("keydown", (e) => {
    const links = [...list.querySelectorAll("a")];
    if (!links.length) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      selected = (selected + (e.key === "ArrowDown" ? 1 : -1) + links.length) % links.length;
      links.forEach((a, i) => a.setAttribute("aria-selected", String(i === selected)));
      links[selected].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      e.preventDefault();
      location.href = (links[selected] || links[0]).href;
    }
  });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
})();
