import BackLink from "@/app/components/BackLink";

/** Affiché immédiatement pendant la préparation de la fiche (sources NVD, CVE.org, CISA, EPSS, OSV, PoC…). */
export default function Loading() {
  return (
    <div className="app page-cve">
      <header className="toolbar">
        <BackLink />
        <span className="toolbar-title">Chargement de la fiche…</span>
        <span />
      </header>
      <main className="cve-main">
        <div className="detail" aria-busy="true">
          <header className="d-head">
            <span className="ring-skel" aria-hidden="true" />
            <div className="d-title">
              <p className="d-sub">Interrogation des sources : NVD, CVE.org, CISA, EPSS, OSV, PoC publics…</p>
            </div>
          </header>
          <div className="skeleton" aria-label="Chargement de la fiche">
            <span />
            <span />
            <span />
            <span />
          </div>
        </div>
      </main>
    </div>
  );
}
