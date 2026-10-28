document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    document.querySelectorAll(".obf").forEach(el => {
      const encoded = el.dataset.obf;
      try {
        const decoded = atob(atob(encoded));
        el.textContent = decoded;
      } catch (e) {
        el.textContent = "unknown";
      }
    });
  }, 1500);
});
