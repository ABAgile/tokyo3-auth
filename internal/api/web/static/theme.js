(() => {
  const root = document.documentElement;
  const key = "tokyo3-theme";
  const button = document.querySelector("[data-theme-toggle]");

  function activeTheme() {
    return root.dataset.theme || "dark";
  }

  function updateButton() {
    if (!button) return;
    const dark = activeTheme() === "dark";
    button.setAttribute("aria-pressed", String(dark));
    button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    button.title = dark ? "Switch to light mode" : "Switch to dark mode";
    const label = button.querySelector("[data-theme-label]");
    if (label) label.textContent = dark ? "Light mode" : "Dark mode";
  }

  button?.addEventListener("click", () => {
    const next = activeTheme() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { window.localStorage.setItem(key, next); } catch (_) {}
    updateButton();
  });

  updateButton();
})();
