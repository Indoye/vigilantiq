"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

/** Retour au tableau, sur l'onglet d'où l'on vient (mémorisé à l'ouverture de la fiche). */
export default function BackLink() {
  const [href, setHref] = useState("/");
  useEffect(() => {
    try {
      const v = sessionStorage.getItem("vq-back");
      if (v && v.startsWith("/") && !v.startsWith("//")) setHref(v);
    } catch {
      /* stockage indisponible */
    }
  }, []);
  return (
    <Link href={href} className="back">
      <svg width="12" height="20" viewBox="0 0 12 20" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M10 2L2 10l8 8" />
      </svg>
      Tableau de veille
    </Link>
  );
}
