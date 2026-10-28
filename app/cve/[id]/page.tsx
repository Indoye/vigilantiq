import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import CveStandalone from "@/app/components/CveStandalone";
import { currentSession } from "@/lib/auth";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { getGuestCve } from "@/lib/publiccve";
import { productName } from "@/lib/format";
import { getStatuses } from "@/lib/userdata";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  return { title: `${id.toUpperCase()} – VigilantIQ` };
}

export default async function CvePage({ params }: Props) {
  const { id: raw } = await params;
  const id = raw.toUpperCase();
  if (!CVE_ID_RE.test(id)) notFound();
  const session = await currentSession();
  // Sans compte : fiche publique (sans IA ni tickets), suivi gardé dans le navigateur.
  const [detail, statuses] = session ? await Promise.all([getCveDetail(id), getStatuses(session.user.id)]) : [await getGuestCve(id), {} as Record<string, never>];
  if (!detail) notFound();

  return (
    <div className="app page-cve">
      <header className="toolbar">
        <Link href="/" className="back">
          <svg width="12" height="20" viewBox="0 0 12 20" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M10 2L2 10l8 8" />
          </svg>
          Tableau de veille
        </Link>
        <span className="toolbar-title">{productName(detail)}</span>
        {session ? <span /> : (
          <Link href={`/connexion?suite=/cve/${id}`} className="public-login">
            Se connecter
          </Link>
        )}
      </header>
      <main className="cve-main">
        <CveStandalone detail={detail} initialStatus={statuses[id] ?? "a_traiter"} guest={!session} />
      </main>
    </div>
  );
}
