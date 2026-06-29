const navToggle = document.querySelector(".nav-toggle");
const nav = document.querySelector("#site-nav");
const themeToggle = document.querySelector("[data-theme-toggle]");
const readingProgress = document.querySelector("[data-reading-progress]");
const themeColor = document.querySelector('meta[name="theme-color"]');
const themeStorageKey = "telekom-security-theme";
const validThemes = ["dark", "light", "system"];
const themeLabels = {
  system: "System",
  light: "Light",
  dark: "Dark"
};
const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

function getStoredTheme() {
  try {
    const storedTheme = window.localStorage.getItem(themeStorageKey);
    if (validThemes.includes(storedTheme)) {
      return storedTheme;
    }

    if (storedTheme) {
      window.localStorage.removeItem(themeStorageKey);
    }
  } catch {
    return "dark";
  }

  return "dark";
}

function getResolvedTheme(theme) {
  return theme === "dark" || (theme === "system" && mediaQuery.matches) ? "dark" : "light";
}

function getNextTheme(theme) {
  const currentIndex = validThemes.indexOf(theme);
  return validThemes[(currentIndex + 1) % validThemes.length];
}

function applyTheme(theme, options = {}) {
  const nextTheme = validThemes.includes(theme) ? theme : "dark";
  const resolvedTheme = getResolvedTheme(nextTheme);

  document.documentElement.dataset.theme = nextTheme;
  document.documentElement.dataset.resolvedTheme = resolvedTheme;
  themeColor?.setAttribute("content", resolvedTheme === "dark" ? "#080b12" : "#f4f7fb");

  if (themeToggle) {
    const followingTheme = getNextTheme(nextTheme);
    themeToggle.dataset.themeValue = nextTheme;
    themeToggle.setAttribute(
      "aria-label",
      `Theme: ${themeLabels[nextTheme]}. Activate for ${themeLabels[followingTheme]}.`
    );
  }

  if (options.persist) {
    try {
      window.localStorage.setItem(themeStorageKey, nextTheme);
    } catch {
      // Ignore storage failures; the selected theme still applies for this page view.
    }
  }
}

applyTheme(getStoredTheme());

themeToggle?.addEventListener("click", () => {
  const currentTheme = document.documentElement.dataset.theme || "dark";
  applyTheme(getNextTheme(currentTheme), { persist: true });
});

mediaQuery.addEventListener("change", () => {
  if ((document.documentElement.dataset.theme || "dark") === "system") {
    applyTheme("system");
  }
});

if (navToggle && nav) {
  navToggle.addEventListener("click", () => {
    const isOpen = navToggle.getAttribute("aria-expanded") === "true";
    const shouldOpen = !isOpen;
    navToggle.setAttribute("aria-expanded", String(shouldOpen));
    navToggle.setAttribute("aria-label", shouldOpen ? "Close navigation" : "Open navigation");
    nav.toggleAttribute("data-open", shouldOpen);
  });
}

function updateReadingProgress() {
  if (!readingProgress) {
    return;
  }

  const scrollableHeight = document.documentElement.scrollHeight - window.innerHeight;
  const progress = scrollableHeight > 0 ? window.scrollY / scrollableHeight : 0;
  readingProgress.style.transform = `scaleX(${Math.min(1, Math.max(0, progress))})`;
}

updateReadingProgress();
window.addEventListener("scroll", updateReadingProgress, { passive: true });
window.addEventListener("resize", updateReadingProgress);

const modal = document.querySelector("[data-image-modal]");
const modalImage = document.querySelector("[data-image-modal-img]");
const modalClose = document.querySelector("[data-image-modal-close]");

function closeModal() {
  if (!modal || !modalImage) {
    return;
  }

  modal.setAttribute("hidden", "");
  modalImage.removeAttribute("src");
  document.body.classList.remove("has-modal");
}

function openModal(image) {
  if (!modal || !modalImage) {
    return;
  }

  modalImage.setAttribute("src", image.currentSrc || image.src);
  modalImage.setAttribute("alt", image.alt || "");
  modal.removeAttribute("hidden");
  document.body.classList.add("has-modal");
}

document.querySelectorAll(".content img").forEach((image) => {
  image.addEventListener("click", (event) => {
    event.preventDefault();
    openModal(image);
  });
});

modal?.addEventListener("click", (event) => {
  if (event.target === modal) {
    closeModal();
  }
});

modalClose?.addEventListener("click", closeModal);

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeModal();
  }
});

window.setTimeout(() => {
  document.querySelectorAll("[data-obf]").forEach((element) => {
    const encoded = element.getAttribute("data-obf");

    if (!encoded) {
      return;
    }

    try {
      element.textContent = window.atob(window.atob(encoded));
    } catch {
      element.textContent = "unknown";
    }
  });
}, 1500);
