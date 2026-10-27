/**
 * Envoi des e-mails (confirmation d'adresse, mot de passe oublié, digest).
 *
 * Deux possibilités, au choix :
 * - SMTP : n'importe quelle boîte mail (Gmail, Outlook, Brevo, OVH…) avec SMTP_HOST, SMTP_USER, SMTP_PASS ;
 * - Resend : RESEND_API_KEY (nécessite un domaine vérifié chez Resend pour écrire à tout le monde).
 * Si les deux sont présents, SMTP est utilisé. Sans aucun des deux, rien n'est envoyé.
 */
import nodemailer, { type Transporter } from "nodemailer";

export interface Mail {
  to: string;
  subject: string;
  html: string;
}

function smtpConfigured(): boolean {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function resendConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY);
}

export function mailConfigured(): boolean {
  return smtpConfigured() || resendConfigured();
}

/** Expéditeur : MAIL_FROM (ou DIGEST_FROM), sinon l'adresse du compte SMTP, sinon l'adresse de test de Resend. */
function from(): string {
  const explicit = process.env.MAIL_FROM || process.env.DIGEST_FROM;
  if (explicit) return explicit;
  if (smtpConfigured()) return `VigilantIQ <${process.env.SMTP_USER}>`;
  return "VigilantIQ <onboarding@resend.dev>";
}

let transporter: Transporter | null = null;

function smtp(): Transporter {
  if (!transporter) {
    const port = Number(process.env.SMTP_PORT || 465);
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      // 465 = TLS direct ; 587 ou 25 = STARTTLS (TLS exigé hors réseau local).
      secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === "true" : port === 465,
      requireTLS: port !== 465 && process.env.SMTP_HOST !== "localhost" && process.env.SMTP_HOST !== "127.0.0.1",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      pool: true,
      maxConnections: 3,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
  }
  return transporter;
}

async function sendSmtp(m: Mail): Promise<boolean> {
  try {
    await smtp().sendMail({ from: from(), to: m.to, subject: m.subject, html: m.html });
    return true;
  } catch (e) {
    console.error(`SMTP : échec de l'envoi « ${m.subject} » (${e instanceof Error ? e.message : e})`);
    return false;
  }
}

async function sendResend(m: Mail): Promise<boolean> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: from(), to: [m.to], subject: m.subject, html: m.html }),
  });
  if (!res.ok) console.error(`Resend a répondu ${res.status} pour « ${m.subject} »`);
  return res.ok;
}

export async function sendMail(m: Mail): Promise<boolean> {
  if (smtpConfigured()) return sendSmtp(m);
  if (resendConfigured()) return sendResend(m);
  console.info(`[e-mail non envoyé : aucun envoi configuré] « ${m.subject} »`);
  return false;
}

/** Envoi groupé (digest). Resend : 100 par appel ; SMTP : connexions réutilisées, 3 en parallèle. */
export async function sendMailBatch(mails: Mail[]): Promise<{ sent: number; failed: number }> {
  let sent = 0;
  let failed = 0;
  if (!mailConfigured()) return { sent, failed: mails.length };

  if (smtpConfigured()) {
    const results = await Promise.all(mails.map(sendSmtp));
    for (const ok of results) ok ? sent++ : failed++;
    return { sent, failed };
  }

  for (let i = 0; i < mails.length; i += 100) {
    const chunk = mails.slice(i, i + 100);
    const res = await fetch("https://api.resend.com/emails/batch", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(chunk.map((m) => ({ from: from(), to: [m.to], subject: m.subject, html: m.html }))),
    });
    if (res.ok) sent += chunk.length;
    else failed += chunk.length;
  }
  return { sent, failed };
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Gabarit sobre pour les e-mails de compte. */
export function accountEmail(title: string, text: string, cta: string, url: string): string {
  return `<!doctype html><html><body style="margin:0;background:#F2F2F7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 12px">
<table width="100%" style="max-width:480px;background:#FFFFFF;border-radius:18px;padding:28px" cellpadding="0" cellspacing="0">
<tr><td style="font-size:22px;font-weight:700;color:#1C1C1E;padding-bottom:10px">${esc(title)}</td></tr>
<tr><td style="font-size:15px;line-height:1.5;color:#3A3A3C;padding-bottom:22px">${esc(text)}</td></tr>
<tr><td><a href="${esc(url)}" style="display:inline-block;background:#007AFF;color:#FFFFFF;text-decoration:none;font-weight:600;font-size:16px;padding:13px 22px;border-radius:12px">${esc(cta)}</a></td></tr>
<tr><td style="font-size:12px;color:#6C6C70;padding-top:22px">Si vous n’êtes pas à l’origine de cette demande, ignorez cet e-mail.</td></tr>
</table></td></tr></table></body></html>`;
}
