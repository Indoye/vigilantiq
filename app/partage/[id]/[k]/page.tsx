import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { BrandName, LogoMark } from "@/app/components/Logo";
import PublicCve from "@/app/components/PublicCve";
import { CVE_ID_RE } from "@/lib/detail";
import { productName } from "@/lib/format";
import { getPublicCve } from "@/lib/publiccve";
import { verifyShareToken } from "@/lib/share";
import { shareTitle } from "@/lib/sharetext";
import { appUrl } from "@/lib/ticketstore";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

type Props = { params: Promise<{ id: string; k: string }> };

async function load(params: Props["params"]) {
  const { id: raw, k } = await params;
  const id = raw.toUpperCase();
  if (!CVE_ID_RE.test(id) || !verifyShareToken(id, k)) return null;
  const detail = await getPublicCve(id);
  return detail ? { id, k, detail } : null;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const r = await load(params);
  if (!r) return { title: "Lien de partage invalide – VigilantIQ", robots: { index: false } };
  const d = r.detail;
  const title = shareTitle({ id: d.id, product: productName(d), priority: d.priority, score: d.score, cvss: d.cvss, kev: Boolean(d.kev), poc: d.exploits?.length ?? 0 });
  const description = (d.ai?.resume ?? d.description).slice(0, 280);
  const url = `${appUrl()}/partage/${r.id}/${r.k}`;
  return {
    title: `${title} – VigilantIQ`,
    description,
    metadataBase: new URL(appUrl()),
    alternates: { canonical: url },
    robots: { index: false, follow: false },
    openGraph: { type: "article", siteName: "VigilantIQ", locale: "fr_FR", title, description, url },
    twitter: { card: "summary_large_image", title, description },
  };
}

export default async function SharedCvePage({ params }: Props) {
  const r = await load(params);
  if (!r) notFound();
  const url = `${appUrl()}/partage/${r.id}/${r.k}`;
  return (
    <div className="app page-cve page-public">
      <header className="toolbar">
        <Link href="/" className="brand" aria-label="VigilantIQ">
          <span className="brand-mark">
            <LogoMark size={22} />
          </span>
          <BrandName />
        </Link>
        <span className="toolbar-title">{productName(r.detail)}</span>
        <Link href={`/connexion?suite=/cve/${r.id}`} className="public-login">
          Se connecter
        </Link>
      </header>
      <main className="cve-main">
        <p className="public-banner">Fiche partagée depuis VigilantIQ, la veille des vulnérabilités expliquée en français.</p>
        <PublicCve detail={r.detail} url={url} />
      </main>
    </div>
  );
}
