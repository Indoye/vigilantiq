"use client";

import { useId, useState } from "react";
import { GLOSSARY, type GlossaryKey } from "@/lib/glossary";

/** Terme technique suivi d'un « ? » qui affiche sa définition au survol, au focus ou au toucher. */
export default function Term({ k, children }: { k: GlossaryKey; children?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span className="term" onMouseLeave={() => setOpen(false)}>
      {children}
      <button
        type="button"
        className="term-q"
        aria-label={`Définition : ${typeof children === "string" ? children : k}`}
        aria-describedby={open ? id : undefined}
        aria-expanded={open}
        onMouseEnter={() => setOpen(true)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => {
          e.stopPropagation();
          e.preventDefault();
          setOpen((o) => !o);
        }}
      >
        ?
      </button>
      {open && (
        <span role="tooltip" id={id} className="term-tip">
          {GLOSSARY[k]}
        </span>
      )}
    </span>
  );
}
