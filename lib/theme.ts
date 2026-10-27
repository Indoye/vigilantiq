"use client";

import { useCallback, useSyncExternalStore } from "react";

/** Apparence choisie : « auto » suit le réglage du système (comme sur iOS/macOS). */
export type ThemePref = "auto" | "light" | "dark";

const KEY = "vq-theme";
const EVENT = "vq-theme-change";
export const THEME_COLORS = { light: "#F2F2F7", dark: "#000000" } as const;

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "auto";
  } catch {
    return "auto";
  }
}

/** Applique le choix sur <html> (data-theme) et sur la couleur de la barre du navigateur. */
export function applyTheme(pref: ThemePref) {
  const root = document.documentElement;
  if (pref === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
  document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((m) => {
    const media = m.getAttribute("data-media") ?? m.getAttribute("media") ?? "";
    if (!m.hasAttribute("data-media")) m.setAttribute("data-media", media);
    const dark = media.includes("dark");
    m.content = pref === "auto" ? (dark ? THEME_COLORS.dark : THEME_COLORS.light) : THEME_COLORS[pref];
  });
}

function subscribe(cb: () => void) {
  window.addEventListener(EVENT, cb);
  window.addEventListener("storage", cb);
  return () => {
    window.removeEventListener(EVENT, cb);
    window.removeEventListener("storage", cb);
  };
}

export function useTheme(): [ThemePref, (p: ThemePref) => void] {
  const pref = useSyncExternalStore(subscribe, read, () => "auto" as ThemePref);
  const set = useCallback((p: ThemePref) => {
    try {
      if (p === "auto") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, p);
    } catch {
      /* stockage indisponible : le choix vaut pour cette page seulement */
    }
    applyTheme(p);
    window.dispatchEvent(new Event(EVENT));
  }, []);
  return [pref, set];
}

/**
 * Script exécuté dans <head> avant l'affichage : pose data-theme tout de suite
 * pour éviter un flash de la mauvaise apparence au chargement.
 */
export const THEME_BOOT_SCRIPT = `(function(){try{var t=localStorage.getItem("${KEY}");if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t);}}catch(e){}})();`;
