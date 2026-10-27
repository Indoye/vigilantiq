import Link from "next/link";

export default function NotFound() {
  return (
    <main className="app nf">
      <div className="card nf-card">
        <h1>Vulnérabilité introuvable</h1>
        <p>Cet identifiant n’existe ni dans la NVD ni sur CVE.org. Vérifiez le format, par exemple CVE-2024-3094.</p>
        <Link href="/" className="btn-primary">
          Revenir au tableau de veille
        </Link>
      </div>
    </main>
  );
}
