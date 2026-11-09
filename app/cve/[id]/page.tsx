import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import BackLink from "@/app/components/BackLink";
import CveStandalone from "@/app/components/CveStandalone";
import { currentTenant } from "@/lib/tenant";
import { CVE_ID_RE, getCveDetail } from "@/lib/detail";
import { getGuestCve } from "@/lib/publiccve";
import { productName } from "@/lib/format";
import { getStatuses } from "@/lib/userdata";
import { cveEngaged } from "@/lib/teamwork";

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
  const session = await currentTenant();
  // Sans compte : fiche publique, sans appel IA ni tickets, en lecture seule.
  const [detail, statuses, engaged] = session
    ? await Promise.all([getCveDetail(id, { orgId: session.orgId }), getStatuses(session.orgId), cveEngaged(session.orgId, id).catch(() => false)])
    : [await getGuestCve(id), {} as Record<string, never>, false];
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
        <CveStandalone detail={detail} initialStatus={statuses[id] ?? "a_traiter"} engaged={engaged} guest={!session} />
      </main>
    </div>
  );
}
