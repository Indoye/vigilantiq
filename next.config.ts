import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // pdfkit lit des fichiers à l'exécution : on le laisse hors du bundle.
  serverExternalPackages: ["pdfkit"],
  // Polices des rapports PDF, lues sur le disque par les routes qui les génèrent.
  outputFileTracingIncludes: {
    "/api/v1/**": ["./assets/fonts/**"],
    "/partage/**": ["./assets/fonts/**"],
    // Scripts de l'agent Parc & correctifs, servis avec l'adresse du serveur et le jeton d'enrôlement
    "/api/v1/agent/**": ["./agent/**"],
  },
};

export default nextConfig;
