/** Décodage d'un vecteur CVSS (v2, v3.x, v4.0) en libellés français, pour les rapports. */

type Table = Record<string, { label: string; values: Record<string, string> }>;

const V3: Table = {
  AV: { label: "Vecteur d'attaque", values: { N: "Réseau (à distance)", A: "Réseau adjacent", L: "Local", P: "Accès physique" } },
  AC: { label: "Complexité de l'attaque", values: { L: "Faible", H: "Élevée" } },
  PR: { label: "Privilèges requis", values: { N: "Aucun", L: "Faibles", H: "Élevés" } },
  UI: { label: "Interaction de l'utilisateur", values: { N: "Aucune", R: "Requise" } },
  S: { label: "Portée", values: { U: "Inchangée", C: "Modifiée (impact au-delà du composant)" } },
  C: { label: "Confidentialité", values: { H: "Impact élevé", L: "Impact faible", N: "Aucun impact" } },
  I: { label: "Intégrité", values: { H: "Impact élevé", L: "Impact faible", N: "Aucun impact" } },
  A: { label: "Disponibilité", values: { H: "Impact élevé", L: "Impact faible", N: "Aucun impact" } },
};

const IMPACT4 = { H: "Impact élevé", L: "Impact faible", N: "Aucun impact" };
const V4: Table = {
  AV: V3.AV,
  AC: V3.AC,
  AT: { label: "Conditions préalables", values: { N: "Aucune", P: "Présentes" } },
  PR: V3.PR,
  UI: { label: "Interaction de l'utilisateur", values: { N: "Aucune", P: "Passive", A: "Active" } },
  VC: { label: "Confidentialité (système vulnérable)", values: IMPACT4 },
  VI: { label: "Intégrité (système vulnérable)", values: IMPACT4 },
  VA: { label: "Disponibilité (système vulnérable)", values: IMPACT4 },
  SC: { label: "Confidentialité (systèmes liés)", values: IMPACT4 },
  SI: { label: "Intégrité (systèmes liés)", values: IMPACT4 },
  SA: { label: "Disponibilité (systèmes liés)", values: IMPACT4 },
};

const IMPACT2 = { N: "Aucun impact", P: "Impact partiel", C: "Impact complet" };
const V2: Table = {
  AV: { label: "Vecteur d'attaque", values: { N: "Réseau (à distance)", A: "Réseau adjacent", L: "Local" } },
  AC: { label: "Complexité de l'attaque", values: { L: "Faible", M: "Moyenne", H: "Élevée" } },
  Au: { label: "Authentification", values: { N: "Aucune", S: "Une fois", M: "Plusieurs fois" } },
  C: { label: "Confidentialité", values: IMPACT2 },
  I: { label: "Intégrité", values: IMPACT2 },
  A: { label: "Disponibilité", values: IMPACT2 },
};

/** [libellé, valeur] pour chaque métrique de base reconnue, dans l'ordre du vecteur. */
export function decodeCvss(vector: string | null | undefined): [string, string][] {
  if (!vector) return [];
  const parts = vector.split("/");
  const head = parts[0];
  const table = head === "CVSS:4.0" ? V4 : head.startsWith("CVSS:3") ? V3 : V2;
  const out: [string, string][] = [];
  for (const p of parts) {
    const [k, v] = p.split(":");
    const m = table[k];
    if (m && m.values[v]) out.push([m.label, m.values[v]]);
  }
  return out;
}

/** Lecture en une phrase : « exploitable à distance, sans privilège ni interaction ». */
export function cvssSentence(vector: string | null | undefined): string {
  if (!vector) return "";
  const get = (k: string) => vector.split("/").find((p) => p.startsWith(`${k}:`))?.split(":")[1];
  const bits: string[] = [];
  const av = get("AV");
  if (av === "N") bits.push("exploitable à distance par le réseau");
  else if (av === "A") bits.push("exploitable depuis le réseau local adjacent");
  else if (av === "L") bits.push("exploitable avec un accès local");
  else if (av === "P") bits.push("exploitable avec un accès physique");
  const pr = get("PR") ?? (get("Au") === "N" ? "N" : undefined);
  const ui = get("UI");
  if (pr === "N" && ui === "N") bits.push("sans privilège ni interaction de l'utilisateur");
  else {
    if (pr === "N") bits.push("sans privilège");
    else if (pr === "L") bits.push("avec un compte à faibles privilèges");
    else if (pr === "H") bits.push("avec des privilèges élevés");
    if (ui === "R" || ui === "A" || ui === "P") bits.push("avec une action de l'utilisateur");
  }
  return bits.length ? `${bits.join(", ")}.`.replace(/^./, (c) => c.toUpperCase()) : "";
}
