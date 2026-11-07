/** Carte « Bien démarrer » : étapes de mise en route d'une organisation, calculées à partir de ses données. */
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { getDb } from "@/db";
import { dwPattern, orgConnector, orgInvite, orgMember, orgSettings, patchDevice, userSettings, watchAccount, watchItem } from "@/db/schema";

export interface Step {
  key: string;
  title: string;
  why: string;
  done: boolean;
  action: { label: string; href: string };
  /** Rôle minimal pour réaliser l'étape */
  role: "analyst" | "admin";
}

const count = async (q: Promise<{ n: number }[]>) => (await q)[0]?.n ?? 0;

export async function onboarding(orgId: string, userId: string): Promise<{ steps: Step[]; hidden: boolean }> {
  const db = getDb();
  const n = sql<number>`count(*)::int`;
  const [settings, watches, accounts, members, invites, connectors, devices, patterns, us] = await Promise.all([
    db.select({ stack: orgSettings.stack }).from(orgSettings).where(eq(orgSettings.orgId, orgId)),
    count(db.select({ n }).from(watchItem).where(eq(watchItem.orgId, orgId))),
    count(db.select({ n }).from(watchAccount).where(eq(watchAccount.orgId, orgId))),
    count(db.select({ n }).from(orgMember).where(eq(orgMember.orgId, orgId))),
    count(db.select({ n }).from(orgInvite).where(and(eq(orgInvite.orgId, orgId), isNull(orgInvite.acceptedAt), gt(orgInvite.expiresAt, new Date())))),
    count(db.select({ n }).from(orgConnector).where(eq(orgConnector.orgId, orgId))),
    count(db.select({ n }).from(patchDevice).where(eq(patchDevice.orgId, orgId))),
    count(db.select({ n }).from(dwPattern).where(eq(dwPattern.orgId, orgId))),
    db.select({ hidden: userSettings.onboardingHidden }).from(userSettings).where(eq(userSettings.userId, userId)),
  ]);
  const steps: Step[] = [
    {
      key: "stack",
      title: "Décrire votre stack",
      why: "Les vulnérabilités qui touchent vos logiciels passent en tête de liste et dans l’e-mail du matin.",
      done: Boolean(settings[0]?.stack?.trim()),
      action: { label: "Ajouter mes technologies", href: "/?vue=stack" },
      role: "analyst",
    },
    {
      key: "watch",
      title: "Surveiller vos domaines et comptes",
      why: "Alerte en cas de fuite de données, de typosquatting ou d’infostealer visant votre entreprise.",
      done: watches + accounts > 0,
      action: { label: "Ajouter un domaine", href: "/?vue=surveillance" },
      role: "analyst",
    },
    {
      key: "team",
      title: "Inviter votre équipe",
      why: "Partagez le suivi des CVE, les alertes et les tickets avec vos collègues.",
      done: members > 1 || invites > 0,
      action: { label: "Inviter un collègue", href: "/compte#organisation" },
      role: "admin",
    },
    {
      key: "darkweb",
      title: "Définir vos motifs dark web",
      why: "Soyez prévenu dès qu’un forum mentionne votre marque, vos domaines ou vos dirigeants.",
      done: patterns > 0,
      action: { label: "Créer un motif", href: "/?vue=dark-web" },
      role: "analyst",
    },
    {
      key: "tools",
      title: "Brancher vos outils",
      why: "Envoyez les CVE prioritaires en un clic vers Jira, ServiceNow, XSOAR ou votre SIEM.",
      done: connectors > 0,
      action: { label: "Configurer une intégration", href: "/compte#organisation" },
      role: "admin",
    },
    {
      key: "parc",
      title: "Installer l’agent sur un poste",
      why: "Voyez quelles machines sont réellement vulnérables et déployez les correctifs.",
      done: devices > 0,
      action: { label: "Ajouter un équipement", href: "/?vue=parc" },
      role: "admin",
    },
  ];
  return { steps, hidden: Boolean(us[0]?.hidden) };
}

export async function setOnboardingHidden(userId: string, hidden: boolean) {
  await getDb()
    .insert(userSettings)
    .values({ userId, onboardingHidden: hidden })
    .onConflictDoUpdate({ target: userSettings.userId, set: { onboardingHidden: hidden, updatedAt: new Date() } });
}
