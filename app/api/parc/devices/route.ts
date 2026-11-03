import { after, NextResponse } from "next/server";
import { fail, noStore, readJson, userOr } from "@/lib/patch/http";
import { correlateDevice, deleteDevice, deviceDetail, runPolicies, updateDevice } from "@/lib/patch/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/** Fiche d'un équipement : inventaire complet, CVE par composant, tâches et journal. */
export async function GET(req: Request) {
  const u = await userOr();
  if (u instanceof NextResponse) return u;
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    return NextResponse.json(await deviceDetail(u.id, id), noStore);
  } catch (e) {
    return fail(e);
  }
}

/** { id, name?, groupName?, tags?, ring? } ou { id, action: "scan" | "reboot" | "correlate" }. */
export async function PATCH(req: Request) {
  const u = await userOr("analyst");
  if (u instanceof NextResponse) return u;
  const b = await readJson(req);
  const id = Number(b.id);
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    if (b.action === "correlate") {
      await deviceDetail(u.id, id);
      after(async () => {
        try {
          await correlateDevice(id);
          await runPolicies(u.id);
        } catch (e) {
          console.error(`[parc] corrélation ${id} : ${e instanceof Error ? e.message : e}`);
        }
      });
      return NextResponse.json({ message: "Analyse des CVE relancée : les résultats arrivent dans quelques instants." });
    }
    return NextResponse.json(await updateDevice(u.id, u.email, id, b));
  } catch (e) {
    return fail(e);
  }
}

export async function DELETE(req: Request) {
  const u = await userOr("admin");
  if (u instanceof NextResponse) return u;
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return NextResponse.json({ error: "Identifiant invalide." }, { status: 400 });
  try {
    await deleteDevice(u.id, u.email, id);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return fail(e);
  }
}
