import { revalidatePath, revalidateTag } from "next/cache";
import { NextResponse } from "next/server";
import { autoConnectors, autoMinPriority, connectorInfo, type ConnectorId } from "@/lib/connectors";
import { ctiHtml, ctiSubject } from "@/lib/cti/notify";
import { markNotified, pendingNotifications, scanAllUsers } from "@/lib/cti/store";
import { runPocMonitor } from "@/lib/exploitstore";
import { getDailyFeed } from "@/lib/feed";
import { buildRemediation } from "@/lib/remediation";
import { getRssSnapshot } from "@/lib/rss";
import { PRIORITY_ORDER } from "@/lib/score";
import { matchStack, parseStack } from "@/lib/stack";
import { mailConfigured, sendMailBatch } from "@/lib/mail";
import { alreadySent, appUrl, sendAndRecord } from "@/lib/ticketstore";
import type { Vuln } from "@/lib/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

const MAX_AUTO_PER_RUN = Number(process.env.CONNECTORS_MAX_PER_RUN || 25);

/**
 * Passe quotidienne (Vercel Cron, avant le digest) :
 * 1. moniteur de PoC (GitHub, PoC-in-GitHub, Exploit-DB) ;
 * 2. envoi automatique des CVE prioritaires aux connecteurs listés dans CONNECTORS_AUTO ;
 * 3. renseignement : analyse des listes de surveillance de chaque utilisateur et e-mail des nouvelles alertes.
 */
export async function GET(req: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.get("authorization") !== `Bearer ${secret}`) {
    return NextResponse.json({ error: "Non autorisé" }, { status: 401 });
  }

  const rss = await getRssSnapshot();
  let feed = await getDailyFeed(rss);
  const watch = feed.vulns.filter((v) => v.priority !== "basse").map((v) => v.id);
  const poc = await runPocMonitor({ watch, rss: rss.items });
  if (poc.created > 0) {
    // De nouveaux PoC changent les scores : on recalcule le flux et on rafraîchit le tableau.
    feed = await getDailyFeed(rss);
    revalidatePath("/");
    revalidateTag("daily-feed", "max");
  }

  // ---------- Envoi automatique ----------
  const minIdx = PRIORITY_ORDER.indexOf(autoMinPriority());
  const stackOnly = process.env.CONNECTORS_STACK_ONLY === "true";
  const teamStack = parseStack(process.env.STACK_KEYWORDS ?? "");
  const eligible: Vuln[] = feed.vulns.filter(
    (v) => PRIORITY_ORDER.indexOf(v.priority) <= minIdx && (!stackOnly || matchStack(v, teamStack).length > 0),
  );

  const base = appUrl();
  const sent: Record<string, { sent: number; failed: number; errors: string[] }> = {};
  for (const id of autoConnectors()) {
    const info = connectorInfo(id);
    const r = (sent[id] = { sent: 0, failed: 0, errors: [] as string[] });
    if (!info.configured) {
      r.errors.push(`non configuré (manque ${info.missing.join(", ")})`);
      continue;
    }
    const done = await alreadySent(id as ConnectorId, eligible.map((v) => v.id));
    const todo = eligible.filter((v) => !done.has(v.id)).slice(0, MAX_AUTO_PER_RUN);
    for (const v of todo) {
      try {
        await sendAndRecord(id, v, buildRemediation(v), base, null);
        r.sent++;
      } catch (e) {
        r.failed++;
        if (r.errors.length < 3) r.errors.push(e instanceof Error ? e.message : String(e));
      }
    }
  }
  for (const [id, r] of Object.entries(sent)) {
    if (r.failed) console.error(`[connecteurs] envoi automatique ${id} : ${r.failed} échec(s) — ${r.errors.join(" | ")}`);
  }

  // ---------- Renseignement sur les menaces ----------
  let cti: Record<string, unknown> = {};
  try {
    const scan = await scanAllUsers();
    let mailed = 0;
    if (mailConfigured()) {
      const groups = await pendingNotifications();
      const mails = groups.map((g) => ({ to: g.email, subject: ctiSubject(g.alerts), html: ctiHtml(g.alerts, base, g.name) }));
      if (mails.length) {
        const { sent: ok } = await sendMailBatch(mails);
        mailed = ok;
        if (ok === mails.length) await markNotified(groups.flatMap((g) => g.alerts.map((a) => a.id)));
      }
    }
    cti = { ...scan, mailed };
  } catch (e) {
    console.error(`[renseignement] passe quotidienne : ${e instanceof Error ? e.message : e}`);
    cti = { error: e instanceof Error ? e.message : String(e) };
  }

  return NextResponse.json({
    cti,
    poc,
    eligible: eligible.length,
    minPriority: autoMinPriority(),
    connectors: sent,
  });
}
