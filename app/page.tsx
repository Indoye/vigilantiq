import Dashboard from "./components/Dashboard";
import { currentFeed } from "@/lib/feedstore";
import { getRssSnapshot } from "@/lib/rss";

// Lit le dernier instantané de la collecte continue (toutes les 10 min) ; régénérée dès qu'une collecte aboutit.
export const revalidate = 300;
export const maxDuration = 300;

export default async function Page() {
  const [rss, feed] = await Promise.all([getRssSnapshot(), currentFeed()]);
  // Page commune à tous (données publiques sur les CVE) ; le compte de chacun se charge ensuite dans le navigateur.
  return <Dashboard feed={feed} initialRss={rss} />;
}
