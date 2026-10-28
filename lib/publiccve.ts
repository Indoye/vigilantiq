import { unstable_cache } from "next/cache.js";
import { getCveDetail } from "./detail";
import type { CveDetail } from "./types";

/**
 * Fiche publique d'une CVE (page de partage) : uniquement des données publiques,
 * sans tickets ni erreurs internes, mise en cache 1 h pour supporter l'afflux d'un réseau social.
 */
export const getPublicCve = (id: string): Promise<CveDetail | null> =>
  unstable_cache(
    async () => {
      const d = await getCveDetail(id, { publicView: true });
      if (!d) return null;
      return { ...d, tickets: [], errors: [] };
    },
    ["public-cve-v1", id],
    { revalidate: 3600, tags: ["public-cve"] },
  )();

/**
 * Fiche pour un visiteur sans compte (onglets publics du tableau) : données publiques, sans appel IA
 * (le résumé du flux du jour est repris côté navigateur), en cache 1 h pour limiter les appels aux sources.
 */
export const getGuestCve = (id: string): Promise<CveDetail | null> =>
  unstable_cache(
    async () => {
      const d = await getCveDetail(id, { publicView: true, noAi: true });
      if (!d) return null;
      return { ...d, tickets: [], errors: [] };
    },
    ["guest-cve-v1", id],
    { revalidate: 3600, tags: ["public-cve"] },
  )();
