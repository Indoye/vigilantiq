/**
 * Logo VigilantIQ « Réticule » : le Q est un écran radar (anneau, faisceau,
 * repères de visée) dont la queue sort en diagonale ; le point jaune est la menace détectée.
 * Aux petites tailles, on retire les détails fins pour garder la lisibilité.
 */
export function LogoMark({ size = 16, detail }: { size?: number; detail?: "full" | "compact" | "tiny" }) {
  const level = detail ?? (size >= 40 ? "full" : size >= 20 ? "compact" : "tiny");
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true" focusable="false">
      {level !== "tiny" && <path d="M50 50 L78.98 42.24 A30 30 0 0 1 71.21 71.21 Z" fill="currentColor" opacity="0.3" />}
      {level === "full" && <circle cx="50" cy="50" r="18" stroke="currentColor" strokeWidth="2.5" opacity="0.6" fill="none" />}
      <circle cx="50" cy="50" r={level === "tiny" ? 30 : 32} stroke="currentColor" strokeWidth={level === "full" ? 6 : level === "compact" ? 8 : 12} fill="none" />
      {level === "full" && <path d="M50 4 V13 M50 87 V96 M4 50 H13 M87 50 H96" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />}
      {level === "compact" && <path d="M50 4 V13 M4 50 H13" stroke="currentColor" strokeWidth="6" strokeLinecap="round" />}
      <line x1="62" y1="62" x2="86" y2="86" stroke="currentColor" strokeWidth={level === "full" ? 7 : level === "compact" ? 9 : 12} strokeLinecap="round" />
      <circle cx="37" cy="38" r={level === "full" ? 4.5 : level === "compact" ? 6 : 8} fill="#ffd60a" />
      {level === "full" && <circle cx="50" cy="50" r="3.5" fill="currentColor" />}
    </svg>
  );
}

export function BrandName() {
  return (
    <span className="brand-name">
      Vigilant<span className="brand-iq">IQ</span>
    </span>
  );
}
