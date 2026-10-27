/**
 * Rendu PDF (A4) des rapports décrits dans reportmodel.ts, avec pdfkit.
 * Police Inter embarquée (assets/fonts, licence OFL) : aucun fichier de police système n'est nécessaire.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import PDFDocument from "pdfkit";
import { pdfText, type Block, type Cell, type ReportMeta, type Tone } from "./reportmodel";

type Doc = InstanceType<typeof PDFDocument>;

const FONT_DIR = path.join(process.cwd(), "assets", "fonts");
let fonts: { regular: Buffer; semibold: Buffer; bold: Buffer } | null = null;
function loadFonts() {
  fonts ??= {
    regular: readFileSync(path.join(FONT_DIR, "Inter-Regular.woff")),
    semibold: readFileSync(path.join(FONT_DIR, "Inter-SemiBold.woff")),
    bold: readFileSync(path.join(FONT_DIR, "Inter-Bold.woff")),
  };
  return fonts;
}

const C = {
  label: "#1c1c1e",
  label2: "#3a3a3c",
  muted: "#6c6c70",
  sep: "#d8d8dc",
  fill: "#f2f2f7",
  card: "#ffffff",
  blue: "#0066cc",
  red: "#d70015",
  orange: "#c93400",
  green: "#1f7a35",
  yellow: "#ffd60a",
};
const TONE: Record<Tone, string> = { normal: C.label, muted: C.muted, red: C.red, orange: C.orange, green: C.green, blue: C.blue };
const TINT: Record<Tone, string> = { normal: "#f2f2f7", muted: "#f2f2f7", red: "#fde8ea", orange: "#fff1e5", green: "#e6f5ea", blue: "#e8f1fc" };

const M = 48; // marges
const FOOT = 34; // hauteur réservée au pied de page

class Writer {
  doc: Doc;
  width: number;
  constructor(meta: ReportMeta) {
    const f = loadFonts();
    this.doc = new PDFDocument({
      size: "A4",
      margins: { top: M, bottom: M + FOOT, left: M, right: M },
      bufferPages: true,
      font: f.regular as unknown as string,
      info: { Title: meta.title, Subject: meta.subject, Author: "VigilantIQ", Creator: "VigilantIQ", Producer: "VigilantIQ" },
      lang: "fr-FR",
      displayTitle: true,
    });
    this.doc.registerFont("r", f.regular);
    this.doc.registerFont("sb", f.semibold);
    this.doc.registerFont("b", f.bold);
    this.width = this.doc.page.width - 2 * M;
  }

  get bottom() {
    return this.doc.page.height - M - FOOT;
  }

  /** Saut de page si moins de `h` points restent sur la page. */
  ensure(h: number) {
    if (this.doc.y + h > this.bottom) this.doc.addPage();
  }

  text(s: string, o: { font?: "r" | "sb" | "b"; size?: number; color?: string; x?: number; width?: number; link?: string; gap?: number; align?: "left" | "right" | "center" } = {}) {
    this.doc
      .font(o.font ?? "r")
      .fontSize(o.size ?? 10)
      .fillColor(o.color ?? C.label)
      .text(pdfText(s), o.x ?? M, undefined, { width: o.width ?? this.width, link: o.link, underline: false, lineGap: o.gap ?? 2, align: o.align });
  }

  height(s: string, font: "r" | "sb" | "b", size: number, width: number) {
    return this.doc.font(font).fontSize(size).heightOfString(pdfText(s), { width, lineGap: 2 });
  }

  // ---------- Blocs ----------

  cover(b: Extract<Block, { type: "cover" }>) {
    const d = this.doc;
    const top = d.y;
    const h = 150;
    d.save().roundedRect(M, top, this.width, h, 14).fill(C.label).restore();
    d.font("sb").fontSize(9).fillColor("#c7c7cc").text(pdfText(b.kicker.toUpperCase()), M + 20, top + 18, { characterSpacing: 0.6, width: this.width - 140 });
    d.font("b").fontSize(26).fillColor("#ffffff").text(pdfText(b.title), M + 20, top + 36, { width: this.width - 140 });
    d.font("r").fontSize(12).fillColor("#e5e5ea").text(pdfText(b.subtitle), M + 20, d.y + 2, { width: this.width - 140 });
    // pastille de priorité
    const pillW = d.font("sb").fontSize(9.5).widthOfString(pdfText(b.pill.text)) + 18;
    const py = top + h - 34;
    d.save().roundedRect(M + 20, py, pillW, 20, 10).fill(TONE[b.pill.tone] === C.muted ? "#8e8e93" : TONE[b.pill.tone]).restore();
    d.font("sb").fontSize(9.5).fillColor("#ffffff").text(pdfText(b.pill.text), M + 29, py + 5, { lineBreak: false });
    // anneau de score
    if (b.score != null) {
      const cx = M + this.width - 62;
      const cy = top + h / 2;
      const r = 38;
      d.save().lineWidth(8).strokeColor("#3a3a3c").circle(cx, cy, r).stroke().restore();
      const color = TONE[b.pill.tone] === C.muted ? "#8e8e93" : TONE[b.pill.tone];
      const a0 = -Math.PI / 2;
      const a1 = a0 + (Math.max(1, b.score) / 100) * Math.PI * 2;
      const steps = 60;
      d.save().lineWidth(8).lineCap("round").strokeColor(color === C.red ? "#ff453a" : color === C.orange ? "#ff9f0a" : color === C.blue ? "#0a84ff" : "#30d158");
      d.moveTo(cx + r * Math.cos(a0), cy + r * Math.sin(a0));
      for (let i = 1; i <= steps; i++) {
        const a = a0 + ((a1 - a0) * i) / steps;
        d.lineTo(cx + r * Math.cos(a), cy + r * Math.sin(a));
      }
      d.stroke().restore();
      d.font("b").fontSize(22).fillColor("#ffffff").text(String(b.score), cx - 30, cy - 14, { width: 60, align: "center" });
      d.font("r").fontSize(7.5).fillColor("#c7c7cc").text("SCORE / 100", cx - 30, cy + 12, { width: 60, align: "center" });
    }
    d.y = top + h + 14;
    // métadonnées
    const colW = this.width / 2;
    let y = d.y;
    b.meta.forEach(([k, v], i) => {
      const x = M + (i % 2) * colW;
      if (i % 2 === 0 && i > 0) y = d.y + 4;
      d.font("sb").fontSize(7.5).fillColor(C.muted).text(pdfText(k.toUpperCase()), x, y, { width: colW - 10, characterSpacing: 0.4 });
      d.font("r").fontSize(9.5).fillColor(C.label).text(pdfText(v), x, d.y + 1, { width: colW - 10, link: /^https?:/.test(v) ? v : undefined });
    });
    d.y += 10;
  }

  h1(text: string) {
    // Un titre ne reste jamais seul en bas de page : on garde la place pour au moins quelques lignes.
    this.ensure(120);
    const d = this.doc;
    d.y += 14;
    d.save().moveTo(M, d.y).lineTo(M + this.width, d.y).lineWidth(0.6).strokeColor(C.sep).stroke().restore();
    d.y += 10;
    this.text(text, { font: "b", size: 14.5 });
    d.y += 4;
  }

  h2(text: string, pageBreak?: boolean) {
    if (pageBreak) this.doc.addPage();
    else this.ensure(50);
    this.doc.y += pageBreak ? 0 : 6;
    this.text(text, { font: "sb", size: pageBreak ? 15 : 11, color: pageBreak ? C.label : C.label2 });
    this.doc.y += pageBreak ? 8 : 3;
  }

  p(b: Extract<Block, { type: "p" }>) {
    const size = b.small ? 8.5 : 10;
    this.ensure(Math.min(60, this.height(b.text, "r", size, this.width)));
    this.text(b.text, { size, color: TONE[b.tone ?? "normal"], gap: 2.5 });
    this.doc.y += 4;
  }

  figures(items: Extract<Block, { type: "figures" }>["items"]) {
    const d = this.doc;
    const n = items.length;
    const gap = 8;
    const w = (this.width - gap * (n - 1)) / n;
    const h = 72;
    this.ensure(h + 6);
    const y = d.y;
    items.forEach((it, i) => {
      const x = M + i * (w + gap);
      d.save().roundedRect(x, y, w, h, 9).fill(C.fill).restore();
      d.font("r").fontSize(8).fillColor(C.label2).text(pdfText(it.label), x + 10, y + 9, { width: w - 20, lineBreak: false, ellipsis: true });
      d.font("b").fontSize(16).fillColor(TONE[it.tone ?? "normal"]).text(pdfText(it.value), x + 10, y + 21, { width: w - 20, lineBreak: false, ellipsis: true });
      if (it.note) d.font("r").fontSize(7.5).fillColor(C.muted).text(pdfText(it.note), x + 10, y + 42, { width: w - 20, height: 24, ellipsis: true, lineGap: 1 });
    });
    d.y = y + h + 8;
  }

  callout(text: string, tone: Tone) {
    const d = this.doc;
    const h = this.height(text, "sb", 9.5, this.width - 24) + 18;
    this.ensure(h + 6);
    const y = d.y;
    d.save().roundedRect(M, y, this.width, h, 9).fill(TINT[tone]).restore();
    d.save().rect(M, y + 6, 3, h - 12).fill(TONE[tone]).restore();
    d.font("sb").fontSize(9.5).fillColor(C.label).text(pdfText(text), M + 14, y + 9, { width: this.width - 24, lineGap: 2 });
    d.y = y + h + 8;
  }

  kv(rows: Extract<Block, { type: "kv" }>["rows"]) {
    const d = this.doc;
    const kw = 140;
    const vw = this.width - kw - 10;
    for (const r of rows) {
      const h = Math.max(this.height(r.k, "sb", 9, kw), this.height(r.v, "r", 9.5, vw)) + 6;
      this.ensure(h);
      const y = d.y;
      d.font("sb").fontSize(9).fillColor(C.muted).text(pdfText(r.k), M, y + 1, { width: kw, lineGap: 2 });
      d.font("r").fontSize(9.5).fillColor(TONE[r.tone ?? "normal"]).text(pdfText(r.v), M + kw + 10, y, { width: vw, lineGap: 2, link: r.link });
      d.y = y + h;
      d.save().moveTo(M, d.y - 3).lineTo(M + this.width, d.y - 3).lineWidth(0.4).strokeColor("#ececf0").stroke().restore();
    }
    d.y += 4;
  }

  bullets(items: Extract<Block, { type: "bullets" }>["items"]) {
    const d = this.doc;
    for (const it of items) {
      const h = this.height(it.text, "r", 9.5, this.width - 14) + (it.sub ? this.height(it.sub, "r", 8.5, this.width - 14) : 0) + 3;
      this.ensure(h);
      const y = d.y;
      d.save().circle(M + 3, y + 6, 1.8).fill(C.muted).restore();
      d.font("r").fontSize(9.5).fillColor(it.link ? C.blue : C.label).text(pdfText(it.text), M + 12, y, { width: this.width - 14, link: it.link, lineGap: 2 });
      if (it.sub) d.font("r").fontSize(8.5).fillColor(C.muted).text(pdfText(it.sub), M + 12, d.y, { width: this.width - 14 });
      d.y += 3;
    }
    d.y += 3;
  }

  table(b: Extract<Block, { type: "table" }>) {
    const d = this.doc;
    if (!b.rows.length) {
      this.p({ type: "p", text: b.empty ?? "Aucune donnée.", tone: "muted" });
      return;
    }
    const pad = 6;
    const widths = b.columns.map((c) => c.width * this.width);
    const header = () => {
      const y = d.y;
      d.save().roundedRect(M, y, this.width, 20, 5).fill(C.fill).restore();
      let x = M;
      b.columns.forEach((c, i) => {
        d.font("sb").fontSize(8).fillColor(C.muted).text(pdfText(c.title.toUpperCase()), x + pad, y + 6, { width: widths[i] - 2 * pad, lineBreak: false, ellipsis: true, characterSpacing: 0.3 });
        x += widths[i];
      });
      d.y = y + 22;
    };
    const cellFont = (c: Cell) => (c.bold ? "sb" : "r");
    this.ensure(48);
    header();
    for (const row of b.rows) {
      const cellH = (c: Cell, w: number) => this.height(c.text, cellFont(c), 8.8, w) + (c.sub ? this.height(c.sub, "r", 7.8, w) + 1 : 0);
      const h = Math.max(...row.map((c, i) => cellH(c, widths[i] - 2 * pad))) + 2 * pad - 2;
      if (d.y + h > this.bottom) {
        d.addPage();
        header();
      }
      const y = d.y;
      let x = M;
      row.forEach((c, i) => {
        const w = widths[i] - 2 * pad;
        // Texte principal ; en bleu s'il s'agit d'un lien sans détail. Le détail (adresse, éditeur…) suit en petit.
        d.font(cellFont(c)).fontSize(8.8).fillColor(c.link && !c.sub ? C.blue : TONE[c.tone ?? "normal"]);
        d.text(pdfText(c.text), x + pad, y + pad - 1, { width: w, link: c.link, lineGap: 2 });
        if (c.sub) d.font("r").fontSize(7.8).fillColor(c.link ? C.blue : C.muted).text(pdfText(c.sub), x + pad, d.y + 1, { width: w, link: c.link, lineGap: 1.5 });
        x += widths[i];
      });
      d.y = y + h;
      d.save().moveTo(M, d.y).lineTo(M + this.width, d.y).lineWidth(0.4).strokeColor("#e5e5ea").stroke().restore();
      d.y += 1;
    }
    d.y += 8;
  }

  steps(groups: Extract<Block, { type: "steps" }>["groups"]) {
    const d = this.doc;
    for (const g of groups) {
      this.ensure(60);
      this.text(g.title.toUpperCase(), { font: "b", size: 8.5, color: TONE[g.tone] });
      d.y += 3;
      g.steps.forEach((s, i) => {
        const w = this.width - 22;
        const h = this.height(`${s.text} [${s.source}]`, "r", 9.5, w) + (s.fr ? this.height(s.fr, "r", 9, w - 10) + 10 : 0) + (s.original ? this.height(s.original, "r", 8.5, w - 10) + 12 : 0) + (s.url ? 14 : 0) + 6;
        this.ensure(Math.min(h, 160));
        const y = d.y;
        d.font("b").fontSize(9.5).fillColor(TONE[g.tone]).text(`${i + 1}.`, M, y, { width: 18 });
        d.font("r").fontSize(9.5).fillColor(C.label).text(pdfText(s.text), M + 22, y, { width: w, lineGap: 2, continued: true });
        d.font("sb").fontSize(8).fillColor(C.muted).text(`   ${pdfText(s.source)}`, { lineGap: 2 });
        if (s.fr) {
          d.y += 3;
          const hy = d.y;
          const hh = this.height(s.fr, "r", 9, w - 14) + 8;
          d.save().roundedRect(M + 22, hy, w, hh, 5).fill(C.fill).restore();
          d.font("r").fontSize(9).fillColor(C.label2).text(pdfText(s.fr), M + 29, hy + 4, { width: w - 14, lineGap: 2 });
          d.y = hy + hh;
        }
        if (s.original) {
          d.y += 3;
          d.font("sb").fontSize(7.5).fillColor(C.muted).text(s.fr ? "TEXTE D'ORIGINE" : "TEXTE DE LA SOURCE (ANGLAIS)", M + 22, d.y, { width: w, characterSpacing: 0.3 });
          d.font("r").fontSize(8.5).fillColor(C.muted).text(pdfText(s.original), M + 22, d.y + 1, { width: w, lineGap: 2 });
        }
        if (s.url) d.font("r").fontSize(8.5).fillColor(C.blue).text(s.url, M + 22, d.y + 2, { width: w, link: s.url });
        d.y += 7;
      });
      d.y += 4;
    }
  }

  footer(label: string, generated: string) {
    const d = this.doc;
    const range = d.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      d.switchToPage(i);
      const oldBottom = d.page.margins.bottom;
      d.page.margins.bottom = 0;
      const y = d.page.height - M - 6;
      d.save().moveTo(M, y - 8).lineTo(M + this.width, y - 8).lineWidth(0.4).strokeColor(C.sep).stroke().restore();
      d.font("r").fontSize(7.5).fillColor(C.muted);
      d.text(pdfText(`VigilantIQ · ${label} · ${generated} · Diffusion interne`), M, y, { width: this.width - 60, lineBreak: false, ellipsis: true });
      d.text(`Page ${i - range.start + 1} / ${range.count}`, M + this.width - 60, y, { width: 60, align: "right", lineBreak: false });
      d.page.margins.bottom = oldBottom;
    }
  }

  render(blocks: Block[]) {
    for (const b of blocks) {
      switch (b.type) {
        case "cover": this.cover(b); break;
        case "h1": this.h1(b.text); break;
        case "h2": this.h2(b.text, b.pageBreak); break;
        case "p": this.p(b); break;
        case "figures": this.figures(b.items); break;
        case "callout": this.callout(b.text, b.tone); break;
        case "kv": this.kv(b.rows); break;
        case "bullets": this.bullets(b.items); break;
        case "table": this.table(b); break;
        case "steps": this.steps(b.groups); break;
      }
    }
  }
}

/** Produit le PDF complet en mémoire. */
export function renderPdf(meta: ReportMeta, blocks: Block[], generatedLabel: string): Promise<Buffer> {
  const w = new Writer(meta);
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    w.doc.on("data", (c: Buffer) => chunks.push(c));
    w.doc.on("end", () => resolve(Buffer.concat(chunks)));
    w.doc.on("error", reject);
    try {
      w.render(blocks);
      w.footer(meta.footer, generatedLabel);
      w.doc.end();
    } catch (e) {
      reject(e);
    }
  });
}
