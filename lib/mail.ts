/** Envoi d'e-mails transactionnels via Resend. Sans clé, les liens sont écrits dans les journaux du serveur. */

export function mailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY);
}

const FROM = () => process.env.DIGEST_FROM || "VigilantIQ <onboarding@resend.dev>";

export interface Mail {
  to: string;
  subject: string;
  html: string;
}

export async function sendMail(m: Mail): Promise<boolean> {
  if (!mailConfigured()) {
    console.info(`[e-mail non envoyé, RESEND_API_KEY absente] à ${m.to} : ${m.subject}`);
    return false;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: FROM(), to: [m.to], subject: m.subject, html: m.html }),
  });
  if (!res.ok) console.error(`Resend a répondu ${res.status} pour ${m.subject}`);
  return res.ok;
}

/** Jusqu'à 100 e-mails par appel (API batch de Resend). */
export async function sendMailBatch(mails: Mail[]): Promise<{ sent: number; failed: number }> {
  let sent = 0;
  let failed = 0;
  if (!mailConfigured()) return { sent, failed: mails.length };
  for (let i = 0; i < mails.length; i += 100) {
    const chunk = mails.slice(i, i + 100);
    const res = await fetch("https://api.resend.com/emails/batch", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(chunk.map((m) => ({ from: FROM(), to: [m.to], subject: m.subject, html: m.html }))),
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
