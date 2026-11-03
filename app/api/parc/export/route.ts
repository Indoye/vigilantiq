import { NextResponse } from "next/server";
import { fail, userOr } from "@/lib/patch/http";
import { exportCsv } from "@/lib/patch/store";

export const dynamic = "force-dynamic";

/** CVE non corrigées du parc au format CSV (séparateur « ; », ouvrable dans Excel). */
export async function GET() {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  try {
    const csv = await exportCsv(u.id);
    return new NextResponse(csv, {
      headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="vigilantiq-parc-${new Date().toISOString().slice(0, 10)}.csv"`, "Cache-Control": "private, no-store" },
    });
  } catch (e) {
    return fail(e);
  }
}
