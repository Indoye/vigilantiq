import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import BackLink from "@/app/components/BackLink";
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
  // Sans compte : fiche publique, sans appel IA ni tickets, en lecture seule.
  const [detail, statuses] = session ? await Promise.all([getCveDetail(id), getStatuses(session.user.id)]) : [await getGuestCve(id), {} as Record<string, never>];
  if (!detail) notFound();

  return (
    <div className="app page-cve">
      <header className="toolbar">
        <BackLink />
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
