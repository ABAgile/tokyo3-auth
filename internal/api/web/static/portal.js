(() => {
  const root = document.documentElement;
  const body = document.body;
  const toggle = document.querySelector("[data-portal-nav-toggle]");
  const sidebar = document.getElementById("portal-sidebar");
  const backdrop = document.querySelector("[data-portal-nav-backdrop]");
  const narrow = window.matchMedia("(max-width: 1023px)");

  if (!toggle || !sidebar || !backdrop) return;

  let returnFocus = null;

  function focusableElements() {
    return [...sidebar.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )];
  }

  function isOpen() {
    return body.classList.contains("portal-nav-open");
  }

  function syncAccessibility() {
    const open = isOpen();
    const hidden = narrow.matches && !open;
    const label = toggle.querySelector(".sr-only");
    sidebar.setAttribute("aria-hidden", String(hidden));
    sidebar.inert = hidden;
    toggle.setAttribute("aria-expanded", String(open));
    if (label) label.textContent = open ? "Close navigation" : "Open navigation";
  }

  function openNavigation() {
    if (!narrow.matches) return;
    returnFocus = document.activeElement;
    body.classList.add("portal-nav-open");
    syncAccessibility();
    const active = sidebar.querySelector("a.active");
    const first = focusableElements()[0];
    (active || first)?.focus();
  }

  function closeNavigation({ restoreFocus = true } = {}) {
    body.classList.remove("portal-nav-open");
    syncAccessibility();
    if (restoreFocus && returnFocus instanceof HTMLElement) returnFocus.focus();
    returnFocus = null;
  }

  toggle.addEventListener("click", () => {
    if (isOpen()) closeNavigation();
    else openNavigation();
  });
  backdrop.addEventListener("click", () => closeNavigation());

  document.addEventListener("keydown", (event) => {
    if (!isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeNavigation();
      return;
    }
    if (event.key !== "Tab") return;

    const elements = focusableElements();
    if (elements.length === 0) return;
    const first = elements[0];
    const last = elements[elements.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  narrow.addEventListener("change", () => {
    closeNavigation({ restoreFocus: false });
    syncAccessibility();
  });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    window.setTimeout(() => { button.textContent = original; }, 1200);
  });

  root.classList.add("js");
  syncAccessibility();
})();
