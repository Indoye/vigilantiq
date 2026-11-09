/**
 * Catalogue initial des applications tierces suivies (Windows et macOS) : nom affiché (« Programmes et
 * fonctionnalités », dossier Applications ou formule Homebrew) → produit CPE de la NVD (pour trouver les CVE)
 * et identifiant winget (mise à jour sous Windows ; sur Mac, Homebrew quand il gère l'application).
 * Une entrée sans identifiant winget est surveillée (CVE affichées) mais pas mise à jour automatiquement.
 */

export interface CatalogApp {
  /** Clé stable du catalogue */
  id: string;
  label: string;
  /** Reconnaît le nom affiché (DisplayName) */
  match: RegExp;
  /** Exclut des variantes (outils annexes, mises à jour) */
  exclude?: RegExp;
  cpeVendor: string;
  cpeProduct: string;
  winget?: string;
}

export const APP_CATALOG: CatalogApp[] = [
  { id: "chrome", label: "Google Chrome", match: /^google chrome$/i, cpeVendor: "google", cpeProduct: "chrome", winget: "Google.Chrome" },
  { id: "firefox", label: "Mozilla Firefox", match: /^(mozilla )?firefox\b/i, exclude: /\besr\b/i, cpeVendor: "mozilla", cpeProduct: "firefox", winget: "Mozilla.Firefox" },
  { id: "firefox-esr", label: "Mozilla Firefox ESR", match: /^(mozilla )?firefox\b.*\besr\b/i, cpeVendor: "mozilla", cpeProduct: "firefox_esr", winget: "Mozilla.Firefox.ESR" },
  { id: "thunderbird", label: "Mozilla Thunderbird", match: /^(mozilla )?thunderbird\b/i, cpeVendor: "mozilla", cpeProduct: "thunderbird", winget: "Mozilla.Thunderbird" },
  { id: "edge", label: "Microsoft Edge", match: /^microsoft edge$/i, cpeVendor: "microsoft", cpeProduct: "edge_chromium", winget: "Microsoft.Edge" },
  { id: "vscode", label: "Visual Studio Code", match: /^(microsoft )?visual studio code\b/i, cpeVendor: "microsoft", cpeProduct: "visual_studio_code", winget: "Microsoft.VisualStudioCode" },
  { id: "7zip", label: "7-Zip", match: /^7-zip\b/i, cpeVendor: "7-zip", cpeProduct: "7-zip", winget: "7zip.7zip" },
  { id: "winrar", label: "WinRAR", match: /^winrar\b/i, cpeVendor: "rarlab", cpeProduct: "winrar", winget: "RARLab.WinRAR" },
  { id: "notepadpp", label: "Notepad++", match: /^notepad\+\+/i, cpeVendor: "notepad-plus-plus", cpeProduct: "notepad\\+\\+", winget: "Notepad++.Notepad++" },
  { id: "vlc", label: "VLC media player", match: /^vlc( media player)?\b/i, cpeVendor: "videolan", cpeProduct: "vlc_media_player", winget: "VideoLAN.VLC" },
  { id: "acrobat-reader", label: "Adobe Acrobat Reader", match: /^adobe acrobat( reader)?( dc)?( \(64-bit\))?$/i, cpeVendor: "adobe", cpeProduct: "acrobat_reader_dc", winget: "Adobe.Acrobat.Reader.64-bit" },
  { id: "foxit-reader", label: "Foxit PDF Reader", match: /^foxit (pdf )?reader\b/i, cpeVendor: "foxit", cpeProduct: "pdf_reader", winget: "Foxit.FoxitReader" },
  { id: "libreoffice", label: "LibreOffice", match: /^libreoffice\b/i, exclude: /help pack|language pack/i, cpeVendor: "libreoffice", cpeProduct: "libreoffice", winget: "TheDocumentFoundation.LibreOffice" },
  { id: "putty", label: "PuTTY", match: /^putty release\b|^putty\b/i, cpeVendor: "putty", cpeProduct: "putty", winget: "PuTTY.PuTTY" },
  { id: "winscp", label: "WinSCP", match: /^winscp\b/i, cpeVendor: "winscp", cpeProduct: "winscp", winget: "WinSCP.WinSCP" },
  { id: "filezilla", label: "FileZilla Client", match: /^filezilla( client)?\b/i, exclude: /server/i, cpeVendor: "filezilla-project", cpeProduct: "filezilla_client", winget: "TimKosse.FileZilla.Client" },
  { id: "wireshark", label: "Wireshark", match: /^wireshark\b/i, cpeVendor: "wireshark", cpeProduct: "wireshark", winget: "WiresharkFoundation.Wireshark" },
  { id: "git", label: "Git", match: /^git( version [\d.]+)?$/i, cpeVendor: "git-scm", cpeProduct: "git", winget: "Git.Git" },
  { id: "nodejs", label: "Node.js", match: /^node(\.js)?$/i, cpeVendor: "nodejs", cpeProduct: "node.js", winget: "OpenJS.NodeJS.LTS" },
  { id: "keepass", label: "KeePass", match: /^keepass password safe\b/i, cpeVendor: "keepass", cpeProduct: "keepass", winget: "DominikReichl.KeePass" },
  { id: "teamviewer", label: "TeamViewer", match: /^teamviewer\b/i, exclude: /host|meeting/i, cpeVendor: "teamviewer", cpeProduct: "teamviewer", winget: "TeamViewer.TeamViewer" },
  { id: "anydesk", label: "AnyDesk", match: /^anydesk\b/i, cpeVendor: "anydesk", cpeProduct: "anydesk", winget: "AnyDeskSoftwareGmbH.AnyDesk" },
  { id: "docker-desktop", label: "Docker Desktop", match: /^docker desktop\b/i, cpeVendor: "docker", cpeProduct: "desktop", winget: "Docker.DockerDesktop" },
  { id: "slack", label: "Slack", match: /^slack\b/i, cpeVendor: "slack", cpeProduct: "slack", winget: "SlackTechnologies.Slack" },
  { id: "vmware-tools", label: "VMware Tools", match: /^vmware tools$/i, cpeVendor: "vmware", cpeProduct: "tools" },
];

/** Entrée du catalogue correspondant à une application installée, ou null. */
export function matchApp(displayName: string): CatalogApp | null {
  const n = displayName.trim();
  if (!n) return null;
  return APP_CATALOG.find((a) => a.match.test(n) && !(a.exclude && a.exclude.test(n))) ?? null;
}

export const appById = (id: string) => APP_CATALOG.find((a) => a.id === id) ?? null;
