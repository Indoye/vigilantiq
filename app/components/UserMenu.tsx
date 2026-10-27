"use client";

import { navigate } from "@/lib/nav";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { authClient } from "@/lib/auth-client";
import { AppearanceSegmented } from "./Appearance";
import { initials, type Me } from "./useMe";

export function Avatar({ me, size = 30 }: { me: Pick<Me, "user">; size?: number }) {
  const [broken, setBroken] = useState(false);
  if (me.user.image && !broken) {
    // eslint-disable-next-line @next/next/no-img-element
    return <img className="avatar" src={me.user.image} alt="" width={size} height={size} onError={() => setBroken(true)} referrerPolicy="no-referrer" />;
  }
  return (
    <span className="avatar avatar-txt" style={{ width: size, height: size, fontSize: size * 0.4 }} aria-hidden="true">
      {initials(me.user.name, me.user.email)}
    </span>
  );
}

export default function UserMenu({ me }: { me: Me | null }) {
  const [open, setOpen] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!me) return <span className="avatar avatar-skel" aria-hidden="true" />;

  const signOut = async () => {
    setLeaving(true);
    await authClient.signOut();
    navigate("/connexion");
  };

  return (
    <div className="usermenu" ref={ref}>
      <button type="button" className="avatar-btn" aria-haspopup="menu" aria-expanded={open} aria-label={`Compte de ${me.user.name || me.user.email}`} onClick={() => setOpen(!open)}>
        <Avatar me={me} />
      </button>
      {open && (
        <div className="menu" role="menu">
          <div className="menu-head">
            <Avatar me={me} size={40} />
            <div className="menu-id">
              <span className="menu-name">{me.user.name || "Sans nom"}</span>
              <span className="menu-mail">{me.user.email}</span>
            </div>
          </div>
          <div className="menu-appear">
            <span className="menu-appear-label">Apparence</span>
            <AppearanceSegmented />
          </div>
          <Link href="/compte" role="menuitem" className="menu-item" onClick={() => setOpen(false)}>
            Mon compte et préférences
          </Link>
          <button type="button" role="menuitem" className="menu-item menu-danger" onClick={signOut} disabled={leaving}>
            {leaving ? "Déconnexion…" : "Se déconnecter"}
          </button>
        </div>
      )}
    </div>
  );
}
