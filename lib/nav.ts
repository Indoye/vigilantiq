/** Navigation complète (rechargement), interceptable par l'aperçu autonome. */
export function navigate(href: string): void {
  const hook = (globalThis as { __vigilantiqNavigate?: (h: string) => void }).__vigilantiqNavigate;
  if (hook) hook(href);
  else window.location.href = href;
}
