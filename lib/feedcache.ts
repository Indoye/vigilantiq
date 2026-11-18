import { currentFeed } from "./feedstore";

/** Flux servi par l'API v1 : dernier instantané de la collecte continue. */
export const getCachedFeed = () => currentFeed();
