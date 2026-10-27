/** Outils communs aux routes qui renvoient un rapport PDF. */
import type { ReportContext } from "./reportmodel";

export function pdfResponse(pdf: Buffer, filename: string, inline: boolean): Response {
  return new Response(new Uint8Array(pdf), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `${inline ? "inline" : "attachment"}; filename="${filename}"`,
      "Content-Length": String(pdf.length),
      "Cache-Control": "private, no-store",
    },
  });
}

export function generatedLabel(ctx: Pick<ReportContext, "generatedAt">): string {
  const d = ctx.generatedAt;
  return `généré le ${d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", timeZone: "UTC" })} à ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" })} UTC`;
}

/** 2026-10-27 */
export function stamp(d: Date): string {
  return d.toISOString().slice(0, 10);
}
