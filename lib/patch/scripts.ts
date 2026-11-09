/**
 * Scripts de l'agent (dossier agent/ du projet) : lus sur le disque, l'adresse du serveur et le jeton d'enrôlement
 * y sont injectés au téléchargement. Le script PowerShell est servi avec une marque d'ordre des octets (BOM) pour que
 * Windows PowerShell 5.1 lise correctement les accents.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export type AgentOs = "windows" | "linux" | "macos";
export const AGENT_FILE: Record<AgentOs, string> = { windows: "vigilantiq-agent.ps1", linux: "vigilantiq-agent.py", macos: "vigilantiq-agent.js" };
export const AGENT_OSES: AgentOs[] = ["windows", "linux", "macos"];

const cache = new Map<AgentOs, string>();
function raw(os: AgentOs): string {
  let s = cache.get(os);
  if (!s) {
    s = readFileSync(join(process.cwd(), "agent", AGENT_FILE[os]), "utf8").replace(/^﻿/, "");
    cache.set(os, s);
  }
  return s;
}

const SAFE_URL = /^https?:\/\/[A-Za-z0-9.\-:[\]]+$/;
const SAFE_TOKEN = /^(vqe_[A-Za-z0-9_-]{40,80})?$/;

/** Script prêt à l'emploi : avec le jeton pour une installation, sans jeton pour une mise à jour de l'agent. */
export function agentScript(os: AgentOs, server: string, token = ""): string {
  if (!SAFE_URL.test(server)) throw new Error("Adresse du serveur invalide pour l'agent");
  if (!SAFE_TOKEN.test(token)) throw new Error("Jeton d'enrôlement invalide");
  return raw(os).replace("__VQ_SERVER__", server).replace("__VQ_ENROLL_TOKEN__", token);
}

/** Commandes d'installation affichées dans la console. */
export function installCommands(os: AgentOs, installerUrl: string): string[] {
  if (os === "windows")
    return [
      "Dans une invite PowerShell lancée en administrateur :",
      `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; Invoke-WebRequest -UseBasicParsing -Uri '${installerUrl}' -OutFile "$env:TEMP\\vigilantiq-agent.ps1"`,
      'powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\\vigilantiq-agent.ps1" -Install',
      "Déploiement en masse : distribuez le même script par GPO, Intune ou SCCM avec le paramètre -Install (exécution en SYSTEM).",
    ];
  if (os === "macos")
    return [
      "Dans le Terminal, avec un compte administrateur (macOS 12 ou plus récent, Intel ou Apple Silicon ; aucune dépendance) :",
      `curl -fsSL '${installerUrl}' -o /tmp/vigilantiq-agent.js`,
      "sudo osascript -l JavaScript /tmp/vigilantiq-agent.js install /tmp/vigilantiq-agent.js",
      "Déploiement en masse : la même commande dans un script de votre MDM (Jamf, Kandji, Intune, Mosyle…), exécuté en root.",
    ];
  return [
    "En root (Python 3.6+ requis : présent par défaut sur Debian et Ubuntu ; sur RHEL, Rocky et AlmaLinux minimal, « dnf install python3 ») :",
    `curl -fsSL '${installerUrl}' -o /tmp/vigilantiq-agent.py`,
    "sudo python3 /tmp/vigilantiq-agent.py install",
    "Déploiement en masse : la même commande dans Ansible, Salt ou cloud-init.",
  ];
}
