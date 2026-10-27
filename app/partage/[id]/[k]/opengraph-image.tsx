import { readFile } from "node:fs/promises";
import path from "node:path";
import { ImageResponse } from "next/og";
import { CVE_ID_RE } from "@/lib/detail";
import { productName } from "@/lib/format";
import { getPublicCve } from "@/lib/publiccve";
import { PRIORITY_LABEL } from "@/lib/score";
import { verifyShareToken } from "@/lib/share";

export const alt = "Fiche de vulnérabilité VigilantIQ";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const PRIO_COLOR = { urgente: "#ff453a", haute: "#ff9f0a", moyenne: "#0a84ff", basse: "#30d158" } as const;

/** Aperçu affiché par LinkedIn, X, Reddit… quand le lien est partagé. */
export default async function Image({ params }: { params: Promise<{ id: string; k: string }> }) {
  const { id: raw, k } = await params;
  const id = raw.toUpperCase();
  const ok = CVE_ID_RE.test(id) && verifyShareToken(id, k);
  const d = ok ? await getPublicCve(id) : null;
  const dir = path.join(process.cwd(), "assets", "fonts");
  const [bold, semi] = await Promise.all([readFile(path.join(dir, "Inter-Bold.woff")), readFile(path.join(dir, "Inter-SemiBold.woff"))]);

  const color = d ? PRIO_COLOR[d.priority] : "#0a84ff";
  const product = d ? productName(d) : "Vulnérabilité";
  const exploited = d ? (d.kev ? "Exploitée (CISA KEV)" : (d.exploits?.length ?? 0) > 0 ? `${d.exploits!.length} PoC public${d.exploits!.length > 1 ? "s" : ""}` : null) : null;
  const facts = d
    ? [d.cvss != null ? `CVSS ${d.cvss.toFixed(1).replace(".", ",")}` : null, d.epss != null ? `EPSS ${Math.round(d.epss * 1000) / 10} %` : null, exploited].filter(Boolean)
    : [];
  const score = d?.score ?? 0;
  const R = 92;
  const C = 2 * Math.PI * R;

  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", background: "#000000", color: "#ffffff", padding: "64px 72px", fontFamily: "Inter" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <svg width="64" height="64" viewBox="0 0 100 100">
            <rect width="100" height="100" rx="22" fill="#0a84ff" />
            <g transform="translate(12 12) scale(0.76)" fill="none" stroke="#ffffff" strokeLinecap="round">
              <path d="M50 50 L78.98 42.24 A30 30 0 0 1 71.21 71.21 Z" fill="#ffffff" fillOpacity="0.3" stroke="none" />
              <circle cx="50" cy="50" r="32" strokeWidth="7" />
              <path d="M50 4 V13 M50 87 V96 M4 50 H13 M87 50 H96" strokeWidth="5" />
              <path d="M62 62 L86 86" strokeWidth="8" />
              <circle cx="37" cy="38" r="5.5" fill="#ffd60a" stroke="none" />
            </g>
          </svg>
          <div style={{ display: "flex", fontSize: 34, fontWeight: 700 }}>
            Vigilant<span style={{ color: "#409cff" }}>IQ</span>
          </div>
        </div>

        <div style={{ display: "flex", flex: 1, alignItems: "center", justifyContent: "space-between", gap: 48 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 18, maxWidth: 760 }}>
            {d && (
              <div style={{ display: "flex" }}>
                <div style={{ display: "flex", background: color, color: d.priority === "haute" ? "#1c1c1e" : "#ffffff", fontSize: 26, fontWeight: 600, padding: "8px 22px", borderRadius: 999 }}>
                  Priorité {PRIORITY_LABEL[d.priority].toLowerCase()}
                </div>
              </div>
            )}
            <div style={{ display: "flex", fontSize: 76, fontWeight: 700, letterSpacing: -2, lineHeight: 1.05 }}>{id}</div>
            <div style={{ display: "flex", fontSize: 40, fontWeight: 600, color: "#ebebf5", lineHeight: 1.2 }}>{product.length > 60 ? product.slice(0, 59) + "…" : product}</div>
            {facts.length > 0 && <div style={{ display: "flex", fontSize: 28, color: "#aeaeb2", fontWeight: 600 }}>{facts.join("  ·  ")}</div>}
          </div>
          {d && (
            <div style={{ display: "flex", position: "relative", width: 220, height: 220, alignItems: "center", justifyContent: "center" }}>
              <svg width="220" height="220" viewBox="0 0 220 220" style={{ position: "absolute", top: 0, left: 0 }}>
                <circle cx="110" cy="110" r={R} stroke="#2c2c2e" strokeWidth="22" fill="none" />
                <circle cx="110" cy="110" r={R} stroke={color} strokeWidth="22" fill="none" strokeLinecap="round" strokeDasharray={`${(C * Math.max(1, score)) / 100} ${C}`} transform="rotate(-90 110 110)" />
              </svg>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div style={{ display: "flex", fontSize: 72, fontWeight: 700 }}>{score}</div>
                <div style={{ display: "flex", fontSize: 20, color: "#aeaeb2", fontWeight: 600 }}>SCORE / 100</div>
              </div>
            </div>
          )}
        </div>
      </div>
    ),
    {
      ...size,
      fonts: [
        { name: "Inter", data: bold, weight: 700, style: "normal" },
        { name: "Inter", data: semi, weight: 600, style: "normal" },
      ],
    },
  );
}
