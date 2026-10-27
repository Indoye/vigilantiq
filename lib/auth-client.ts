"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();

const ERRORS: Record<string, string> = {
  INVALID_EMAIL_OR_PASSWORD: "E-mail ou mot de passe incorrect.",
  USER_ALREADY_EXISTS: "Un compte existe déjà avec cette adresse. Connectez-vous.",
  USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: "Un compte existe déjà avec cette adresse. Connectez-vous.",
  PASSWORD_TOO_SHORT: "Le mot de passe doit contenir au moins 10 caractères.",
  PASSWORD_TOO_LONG: "Le mot de passe est trop long.",
  INVALID_EMAIL: "Cette adresse e-mail n’est pas valide.",
  INVALID_PASSWORD: "Mot de passe actuel incorrect.",
  INVALID_TOKEN: "Ce lien n’est plus valable. Demandez-en un nouveau.",
  EMAIL_NOT_VERIFIED: "Confirmez d’abord votre adresse e-mail.",
  CREDENTIAL_ACCOUNT_NOT_FOUND: "Ce compte utilise la connexion Google, sans mot de passe.",
  TOO_MANY_REQUESTS: "Trop de tentatives. Patientez une minute puis réessayez.",
};

/** Message d'erreur en français à partir d'une erreur Better Auth. */
export function authError(e: { code?: string; message?: string; status?: number } | null | undefined): string {
  if (!e) return "Une erreur inconnue s’est produite.";
  if (e.status === 429) return ERRORS.TOO_MANY_REQUESTS;
  if (e.code && ERRORS[e.code]) return ERRORS[e.code];
  if (e.message && /réservées/.test(e.message)) return e.message;
  return e.message || "La demande n’a pas abouti. Réessayez.";
}
