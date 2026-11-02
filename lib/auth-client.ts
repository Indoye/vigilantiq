"use client";

import { twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

// La redirection vers l'étape « code à 6 chiffres » est gérée par le formulaire de connexion lui-même.
export const authClient = createAuthClient({ plugins: [twoFactorClient()] });

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
  INVALID_CODE: "Code incorrect. Vérifiez l’heure de votre téléphone et réessayez.",
  INVALID_TWO_FACTOR_COOKIE: "La vérification a expiré. Reconnectez-vous avec votre mot de passe.",
  TOTP_NOT_ENABLED: "La double authentification n’est pas activée.",
  TOTP_ALREADY_ENABLED: "La double authentification est déjà activée.",
  INVALID_BACKUP_CODE: "Code de secours incorrect ou déjà utilisé.",
  TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE: "Trop d’essais : patientez quelques minutes puis réessayez.",
  ACCOUNT_TEMPORARILY_LOCKED: "Trop de codes incorrects : la vérification est bloquée quelques minutes.",
};

/** Message d'erreur en français à partir d'une erreur Better Auth. */
export function authError(e: { code?: string; message?: string; status?: number } | null | undefined): string {
  if (!e) return "Une erreur inconnue s’est produite.";
  if (e.status === 429) return ERRORS.TOO_MANY_REQUESTS;
  if (e.code && ERRORS[e.code]) return ERRORS[e.code];
  if (e.message && /réservées/.test(e.message)) return e.message;
  return e.message || "La demande n’a pas abouti. Réessayez.";
}
