import Dashboard from "./components/Dashboard";
import { getDailyFeed } from "@/lib/feed";
import { getRssSnapshot } from "@/lib/rss";

// CVE régénérées toutes les heures au plus ; les flux RSS sont ensuite suivis en direct côté navigateur.
export const revalidate = 3600;
export const maxDuration = 300;

export default async function Page() {
  const rss = await getRssSnapshot();
  const feed = await getDailyFeed(rss);
  // Page commune à tous (données publiques sur les CVE) ; le compte de chacun se charge ensuite dans le navigateur.
  return <Dashboard feed={feed} initialRss={rss} />;
}
