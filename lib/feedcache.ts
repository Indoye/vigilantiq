/** Flux du jour mis en cache 30 minutes, partagé par l'API v1 (évite de tout recalculer à chaque appel). */
import { unstable_cache } from "next/cache";
import { getDailyFeed } from "./feed";

export const getCachedFeed = unstable_cache(() => getDailyFeed(), ["daily-feed-api-v1"], { revalidate: 1800, tags: ["daily-feed"] });
