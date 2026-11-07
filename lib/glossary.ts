/** Définitions courtes du jargon, affichées dans les infobulles « ? ». */
export const GLOSSARY = {
  cve: "Identifiant unique d’une vulnérabilité publiée (ex. CVE-2026-12345), attribué par l’organisme MITRE et ses partenaires.",
  cvss: "Note de gravité de 0 à 10 : ce qu’un attaquant pourrait faire si la faille était exploitée. 9 et plus = critique.",
  epss: "Probabilité, estimée chaque jour par le FIRST, que la faille soit exploitée dans les 30 prochains jours. 10 % et plus, c’est élevé.",
  kev: "Catalogue de la CISA (agence américaine de cybersécurité) qui liste les failles réellement exploitées par des attaquants, avec une date limite de correction.",
  ssvc: "Méthode de décision de la CISA qui indique si une faille est exploitée, automatisable et quel est son impact technique.",
  poc: "Preuve de concept : code public qui montre comment exploiter la faille. Sa présence rend une attaque beaucoup plus facile.",
  score: "Score de priorité VigilantIQ (0 à 100) : combine gravité (CVSS), probabilité d’exploitation (EPSS), exploitation confirmée (CISA) et alertes des CERT.",
  echeance: "Date limite de correction : celle fixée par la CISA pour les failles exploitées, sinon un délai recommandé selon la priorité (7, 30 ou 90 jours).",
  ioc: "Indicateur de compromission : adresse IP, domaine, URL ou empreinte de fichier liés à une attaque connue. À rechercher dans vos journaux.",
  c2: "Serveur de commande et de contrôle : machine qui pilote des ordinateurs infectés (botnet).",
  infostealer: "Logiciel malveillant qui vole les mots de passe et cookies enregistrés dans le navigateur d’un poste infecté.",
  typosquat: "Nom de domaine imitant le vôtre (faute de frappe, caractère proche) utilisé pour l’hameçonnage.",
  exposition: "Indice d’exposition VigilantIQ (0 = rien à signaler, 100 = exposition maximale) : échéances dépassées, failles urgentes ou hautes touchant votre stack, alertes critiques récentes et équipements vulnérables.",
  mttr: "Délai moyen de correction : temps entre la détection d’une faille urgente ou haute sur un équipement et son correctif.",
} as const;
export type GlossaryKey = keyof typeof GLOSSARY;
