"use client";

import type { CveDetail } from "@/lib/types";
import CveDetailView from "./CveDetailView";

/** Fiche en lecture seule pour la page publique de partage. */
export default function PublicCve({ detail, url }: { detail: CveDetail; url: string }) {
  return <CveDetailView base={detail} full={detail} status="a_traiter" onStatus={() => {}} standalone publicUrl={url} />;
}
