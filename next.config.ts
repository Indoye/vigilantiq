import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // pdfkit lit des fichiers à l'exécution : on le laisse hors du bundle.
  serverExternalPackages: ["pdfkit"],
  // Polices des rapports PDF, lues sur le disque par les routes qui les génèrent.
  outputFileTracingIncludes: {
    "/api/v1/**": ["./assets/fonts/**"],
  },
};

export default nextConfig;
