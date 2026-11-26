(() => {
  const storageKey = "phishcheck-theme";
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const root = document.documentElement;
  let preference;

  try {
    const saved = localStorage.getItem(storageKey);
    if (saved === "light" || saved === "dark") preference = saved;
  } catch {
    // The switch still works when browser storage is unavailable.
  }

  function applyTheme() {
    const theme = preference ?? (systemTheme.matches ? "dark" : "light");
    root.dataset.theme = theme;
    document.querySelector("#theme-toggle")?.setAttribute("aria-pressed", String(theme === "dark"));
  }

  applyTheme();
  systemTheme.addEventListener("change", applyTheme);

  document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.querySelector("#theme-toggle");
    applyTheme();
    toggle.hidden = false;
    toggle.addEventListener("click", () => {
      preference = root.dataset.theme === "dark" ? "light" : "dark";
      applyTheme();
      try {
        localStorage.setItem(storageKey, preference);
      } catch {
        // Apply the preference for this page even if it cannot be saved.
      }
    });
  });
})();
