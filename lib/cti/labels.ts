/** Libellés français des types de données exposées (catalogue Have I Been Pwned). */
export const DATA_FR: Record<string, string> = {
  "Email addresses": "E-mails",
  Passwords: "Mots de passe",
  Names: "Noms",
  "Phone numbers": "Téléphones",
  "Physical addresses": "Adresses",
  "Dates of birth": "Dates de naissance",
  "IP addresses": "Adresses IP",
  Usernames: "Identifiants",
  "Credit cards": "Cartes bancaires",
  "Partial credit card data": "Cartes (partiel)",
  "Government issued IDs": "Pièces d’identité",
  Genders: "Genres",
  "Email messages": "Messages",
  "Bank account numbers": "Comptes bancaires",
  "Social security numbers": "N° de sécurité sociale",
  "Auth tokens": "Jetons d’accès",
};

export const dataFr = (d: string) => DATA_FR[d] ?? d;
