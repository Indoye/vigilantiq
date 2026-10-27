import { and, eq, inArray } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { NextResponse } from "next/server";
import { dbConfigured, getDb } from "@/db";
import { cveStatus, user, userSettings } from "@/db/schema";
import { digestHtml, digestSlack, digestSubject, selectForDigest } from "@/lib/digest";
import { getDailyFeed } from "@/lib/feed";
import { mailConfigured, sendMailBatch, type Mail } from "@/lib/mail";
import type { Priority } from "@/lib/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/**
 * Appelé chaque matin par Vercel Cron (voir vercel.json).
 * Chaque utilisateur reçoit son propre digest (sa stack, ses préférences, sans les CVE qu'il a déjà traitées).
 * Seules les adresses confirmées reçoivent un e-mail (les comptes Google sont confirmés d'office).
 */
export async function GET(req: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.get("authorization") !== `Bearer ${secret}`) {
    return NextResponse.json({ error: "Non autorisé" }, { status: 401 });
  }

  revalidatePath("/");
  const feed = await getDailyFeed();
  const appUrl = process.env.APP_URL || process.env.BETTER_AUTH_URL || `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL ?? ""}`;
  const result: Record<string, unknown> = { sourceErrors: feed.errors };

  // ---------- e-mails par utilisateur ----------
  if (dbConfigured() && mailConfigured()) {
    const db = getDb();
    const recipients = await db
      .select({
        id: user.id,
        name: user.name,
        email: user.email,
        stack: userSettings.stack,
        minPriority: userSettings.digestMinPriority,
        stackOnly: userSettings.digestStackOnly,
      })
      .from(user)
      .innerJoin(userSettings, eq(userSettings.userId, user.id))
      .where(and(eq(userSettings.digestEnabled, true), eq(user.emailVerified, true)));

    const closedRows = recipients.length
      ? await db
          .select({ userId: cveStatus.userId, cveId: cveStatus.cveId })
          .from(cveStatus)
          .where(and(inArray(cveStatus.userId, recipients.map((r) => r.id)), inArray(cveStatus.status, ["traitee", "non_concernee"])))
      : [];
    const closed = new Map<string, Set<string>>();
    for (const r of closedRows) closed.set(r.userId, (closed.get(r.userId) ?? new Set()).add(r.cveId));

    const mails: Mail[] = [];
    let skipped = 0;
    for (const r of recipients) {
      const items = selectForDigest(feed, r.stack, {
        minPriority: r.minPriority as Priority,
        stackOnly: r.stackOnly,
        closed: closed.get(r.id),
      });
      // Pas d'e-mail vide : on n'écrit que s'il y a quelque chose à faire.
      if (items.length === 0) {
        skipped++;
        continue;
      }
      mails.push({ to: r.email, subject: digestSubject(items, new Date()), html: digestHtml(items, appUrl, r.name) });
    }
    const { sent, failed } = await sendMailBatch(mails);
    result.email = { recipients: recipients.length, sent, failed, skipped };
  }

  // ---------- Slack, pour toute l'équipe ----------
  if (process.env.SLACK_WEBHOOK_URL) {
    const items = selectForDigest(feed, process.env.STACK_KEYWORDS ?? "", { minPriority: "haute" });
    const subject = digestSubject(items, new Date());
    const res = await fetch(process.env.SLACK_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: digestSlack(items, appUrl, subject) }),
    });
    result.slack = res.ok ? "envoyé" : `échec (${res.status})`;
  }

  return NextResponse.json(result);
}
