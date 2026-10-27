/** Navigation complète (rechargement), interceptable par l'aperçu autonome. */
export function navigate(href: string): void {
  const hook = (globalThis as { __veilleNavigate?: (h: string) => void }).__veilleNavigate;
  if (hook) hook(href);
  else window.location.href = href;
}
