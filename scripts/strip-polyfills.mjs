/**
 * Après `next build` : retire les polyfills « nomodule » (navigateurs sans modules ES, antérieurs à 2017),
 * que VigilantIQ ne prend pas en charge (React 19 exige un navigateur récent).
 * Le fichier contenait la réimplémentation de l'objet URL (« password=n.getPassword() »), signalée à tort
 * comme une fuite de secret par les scanners : on l'enlève des manifestes, des pages pré-rendues et du disque.
 */
import { existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const NEXT = ".next";
const root = JSON.parse(readFileSync(join(NEXT, "build-manifest.json"), "utf8"));
const files = (root.polyfillFiles ?? []).filter((f) => f.endsWith(".js"));
if (!files.length) {
  console.log("Polyfills nomodule : aucun.");
  process.exit(0);
}
const names = files.map((f) => f.split("/").pop());
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const tagRe = new RegExp(`<script[^>]*src="[^"]*(?:${names.map(esc).join("|")})[^"]*"[^>]*></script>`, "g");

let manifests = 0;
let pages = 0;
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (name === "build-manifest.json") {
      const j = JSON.parse(readFileSync(p, "utf8"));
      if (Array.isArray(j.polyfillFiles) && j.polyfillFiles.length) {
        j.polyfillFiles = [];
        writeFileSync(p, JSON.stringify(j, null, 2));
        manifests++;
      }
    } else if (name === "middleware-build-manifest.js") {
      const s = readFileSync(p, "utf8");
      const t = s.replace(/"polyfillFiles":\s*\[[^\]]*\]/g, '"polyfillFiles":[]');
      if (t !== s) writeFileSync(p, t), manifests++;
    } else if (/\.(html|rsc)$/.test(name)) {
      const s = readFileSync(p, "utf8");
      const t = s.replace(tagRe, "");
      if (t !== s) writeFileSync(p, t), pages++;
    }
  }
};
walk(NEXT);
for (const f of files) {
  for (const p of [join(NEXT, f), join(NEXT, `${f}.map`)]) if (existsSync(p)) rmSync(p);
}
console.log(`Polyfills nomodule retirés : ${names.join(", ")} (${manifests} manifestes, ${pages} pages pré-rendues).`);
