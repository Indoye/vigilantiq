"use client";

import { useEffect } from "react";
import { applyTheme, useTheme, type ThemePref } from "@/lib/theme";

const OPTIONS: { value: ThemePref; label: string; hint: string }[] = [
  { value: "light", label: "Clair", hint: "Toujours clair" },
  { value: "dark", label: "Sombre", hint: "Toujours sombre" },
  { value: "auto", label: "Automatique", hint: "Suit le réglage de l’appareil" },
];

/** Vignette façon réglage « Apparence » d’iOS. */
function Thumb({ kind }: { kind: ThemePref }) {
  const light = (
    <>
      <rect width="56" height="40" rx="6" fill="#f2f2f7" />
      <rect x="6" y="7" width="44" height="9" rx="3" fill="#ffffff" />
      <rect x="6" y="20" width="44" height="13" rx="3" fill="#ffffff" />
      <rect x="10" y="10" width="16" height="3" rx="1.5" fill="#1c1c1e" />
      <rect x="10" y="24" width="24" height="3" rx="1.5" fill="#c7c7cc" />
      <circle cx="44" cy="26.5" r="3" fill="#007aff" />
    </>
  );
  const dark = (
    <>
      <rect width="56" height="40" rx="6" fill="#000000" />
      <rect x="6" y="7" width="44" height="9" rx="3" fill="#1c1c1e" />
      <rect x="6" y="20" width="44" height="13" rx="3" fill="#1c1c1e" />
      <rect x="10" y="10" width="16" height="3" rx="1.5" fill="#ffffff" />
      <rect x="10" y="24" width="24" height="3" rx="1.5" fill="#48484a" />
      <circle cx="44" cy="26.5" r="3" fill="#0a84ff" />
    </>
  );
  return (
    <svg viewBox="0 0 56 40" width="56" height="40" aria-hidden="true" className="appear-thumb">
      {kind === "light" && light}
      {kind === "dark" && dark}
      {kind === "auto" && (
        <>
          <defs>
            <clipPath id="appear-half">
              <rect x="28" width="28" height="40" />
            </clipPath>
          </defs>
          {light}
          <g clipPath="url(#appear-half)">{dark}</g>
        </>
      )}
    </svg>
  );
}

/** Choix de l’apparence avec vignettes (page Mon compte). */
export function AppearancePicker() {
  const [pref, setPref] = useTheme();
  return (
    <div className="appear" role="radiogroup" aria-label="Apparence">
      {OPTIONS.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={pref === o.value}
          className={`appear-opt${pref === o.value ? " is-on" : ""}`}
          onClick={() => setPref(o.value)}
          title={o.hint}
        >
          <Thumb kind={o.value} />
          <span className="appear-label">{o.label}</span>
          <span className="appear-check" aria-hidden="true" />
        </button>
      ))}
    </div>
  );
}

/** Version compacte (menu du compte). */
export function AppearanceSegmented() {
  const [pref, setPref] = useTheme();
  return (
    <div className="segmented appear-seg" role="radiogroup" aria-label="Apparence">
      {OPTIONS.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={pref === o.value} className={pref === o.value ? "is-on" : ""} onClick={() => setPref(o.value)} title={o.hint}>
          {o.value === "auto" ? "Auto" : o.label}
        </button>
      ))}
    </div>
  );
}

/** Réapplique le choix (couleur de barre comprise) une fois la page montée. */
export function ThemeSync() {
  const [pref] = useTheme();
  useEffect(() => applyTheme(pref), [pref]);
  return null;
}
