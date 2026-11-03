#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VigilantIQ — agent « Parc & correctifs » pour Linux (Debian, Ubuntu, RHEL, Rocky, AlmaLinux).

  sudo python3 vigilantiq-agent.py install     installe le service, enrôle la machine
  sudo python3 vigilantiq-agent.py uninstall   retire le service et la clé de la machine
  sudo python3 vigilantiq-agent.py once        une synchronisation (diagnostic)
  sudo python3 vigilantiq-agent.py status      état de l'agent

Communication sortante uniquement (HTTPS 443), requêtes signées HMAC-SHA256 avec la clé de l'équipement.
L'agent n'exécute que des actions prédéfinies (inventaire, mise à jour de paquets, retour arrière, redémarrage),
et seulement si la tâche est signée avec la clé de l'équipement. Aucun script arbitraire n'est exécuté.
Python 3.6+ et la bibliothèque standard suffisent.
"""
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AGENT_VERSION = "1.0.0"
SERVER = os.environ.get("VQ_SERVER") or "__VQ_SERVER__"
ENROLL_TOKEN = os.environ.get("VQ_ENROLL_TOKEN") or "__VQ_ENROLL_TOKEN__"
STATE_DIR = os.environ.get("VQ_STATE_DIR", "/var/lib/vigilantiq")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
INSTALL_DIR = "/opt/vigilantiq"
INSTALLED = os.path.join(INSTALL_DIR, "agent.py")
UNIT_FILE = "/etc/systemd/system/vigilantiq-agent.service"
CRON_FILE = "/etc/cron.d/vigilantiq-agent"
# Simulation : les commandes de mise à jour sont journalisées mais pas exécutées (tests, démonstration).
DRY_RUN = os.environ.get("VQ_DRY_RUN") == "1"
REBOOT_MESSAGE = "VigilantIQ : redémarrage dans 5 minutes pour terminer l'installation des correctifs."


def log(msg):
    sys.stderr.write("[vigilantiq] %s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    sys.stderr.flush()


def run(cmd, timeout=3600, env=None):
    """Exécute une commande (liste d'arguments, jamais de shell). Renvoie (code, sortie)."""
    if DRY_RUN and cmd and cmd[0] in ("apt-get", "dnf", "yum", "shutdown", "wall"):
        return 0, "[simulation] " + " ".join(cmd)
    try:
        e = dict(os.environ)
        if env:
            e.update(env)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=e)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "%s introuvable" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "%s : délai dépassé" % cmd[0]


def read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


# ---------- État local (clé de l'équipement) ----------


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def server_url():
    s = (load_state().get("server") or SERVER).rstrip("/")
    u = urllib.parse.urlparse(s)
    local = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme != "https" and not (u.scheme == "http" and local):
        raise SystemExit("Adresse du serveur invalide : HTTPS obligatoire (%s)" % s)
    return s


# ---------- HTTP ----------


def http(method, path, body=None, key=None, timeout=120):
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8") if body is not None else b""
    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "vigilantiq-agent/%s (linux)" % AGENT_VERSION}
    if key:
        ts = str(int(time.time()))
        sig = hmac.new(key.encode(), ts.encode() + b"." + data, hashlib.sha256).hexdigest()
        headers.update({"Authorization": "Bearer " + key, "X-VQ-Timestamp": ts, "X-VQ-Signature": "sha256=" + sig})
    req = urllib.request.Request(server_url() + path, data=data if method != "GET" else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except ValueError:
            return e.code, {"error": "HTTP %d" % e.code}


# ---------- Inventaire ----------


def os_release():
    info = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"')
    return info


def machine_id():
    mid = read("/etc/machine-id") or read("/var/lib/dbus/machine-id")
    if not mid:
        mid = hashlib.sha256((socket.gethostname() + read("/sys/class/dmi/id/product_uuid")).encode()).hexdigest()
    return hashlib.sha256(("vigilantiq:" + mid).encode()).hexdigest()[:32]


def local_ip():
    try:
        host = urllib.parse.urlparse(load_state().get("server") or SERVER).hostname or "8.8.8.8"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def pkg_format():
    if shutil.which("dpkg-query"):
        return "deb"
    if shutil.which("rpm"):
        return "rpm"
    return ""


def packages(fmt):
    out = []
    if fmt == "deb":
        code, txt = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${db:Status-Abbrev}\n"], timeout=300)
        for line in txt.splitlines():
            f = line.split("\t")
            if len(f) < 6 or not f[5].startswith("ii"):
                continue
            out.append({"name": f[0].split(":")[0], "version": f[1], "source": f[2] or f[0].split(":")[0], "sourceVersion": f[3] or f[1], "arch": f[4]})
    elif fmt == "rpm":
        code, txt = run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"], timeout=300)
        for line in txt.splitlines():
            f = line.split("\t")
            if len(f) < 6 or f[0] == "gpg-pubkey":
                continue
            ver = ("%s:" % f[1] if f[1] not in ("", "0", "(none)") else "") + "%s-%s" % (f[2], f[3])
            src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", f[5]) if f[5] not in ("", "(none)") else f[0]
            out.append({"name": f[0], "version": ver, "source": src, "arch": f[4]})
    return out


def reboot_pending():
    if os.path.exists("/var/run/reboot-required"):
        return True
    if shutil.which("needs-restarting"):
        code, _ = run(["needs-restarting", "-r"], timeout=120)
        return code == 1
    return False


def is_desktop():
    code, out = run(["systemctl", "get-default"], timeout=10)
    return code == 0 and out.strip() == "graphical.target"


def inventory():
    rel = os_release()
    fmt = pkg_format()
    dmi = lambda n: read("/sys/class/dmi/id/" + n)
    cpu = ""
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem = re.search(r"MemTotal:\s+(\d+)", read("/proc/meminfo"))
    return {
        "hostname": socket.gethostname(),
        "ip": local_ip(),
        "domain": socket.getfqdn().partition(".")[2],
        "user": "",
        "rebootPending": reboot_pending(),
        "appManager": False,
        "os": {
            "family": "linux",
            "name": rel.get("PRETTY_NAME", "Linux"),
            "id": rel.get("ID", ""),
            "idLike": rel.get("ID_LIKE", ""),
            "version": rel.get("VERSION_ID", ""),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "pkg": fmt,
            "desktop": is_desktop(),
        },
        "hardware": {
            "manufacturer": dmi("sys_vendor"),
            "model": dmi("product_name"),
            "biosVendor": dmi("bios_vendor"),
            "biosVersion": dmi("bios_version"),
            "biosDate": dmi("bios_date"),
            "cpu": cpu,
            "ramMb": str(int(mem.group(1)) // 1024) if mem else "",
        },
        "packages": packages(fmt),
    }


# ---------- Actions ----------


def installed_versions(fmt, names):
    vers = {}
    if not names:
        return vers
    if fmt == "deb":
        code, txt = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"] + list(names), timeout=120)
    else:
        code, txt = run(["rpm", "-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"] + list(names), timeout=120)
    for line in txt.splitlines():
        f = line.split("\t")
        if len(f) == 2:
            vers[f[0].split(":")[0]] = f[1]
    return vers


def dnf():
    return "dnf" if shutil.which("dnf") else "yum"


def do_reboot(mode, log_lines):
    if mode == "redemarrer" and reboot_pending():
        code, out = run(["shutdown", "-r", "+5", REBOOT_MESSAGE], timeout=30)
        log_lines.append("Redémarrage programmé dans 5 minutes" if code == 0 else "Redémarrage impossible : " + out[-300:])
        return code == 0
    if mode == "prevenir" and reboot_pending():
        run(["wall", "VigilantIQ : des correctifs ont été installés. Redémarrez la machine dès que possible."], timeout=30)
        log_lines.append("Utilisateurs prévenus : redémarrage nécessaire")
    return False


def job_install(payload):
    fmt = pkg_format()
    lines = []
    bins = sorted({b for it in payload.get("items", []) if it.get("kind") == "package" for b in it.get("binaries", []) if re.match(r"^[A-Za-z0-9.+_-]+$", b)})
    if not bins:
        return "echec", "Aucun paquet à mettre à jour sur ce système.", {}
    before = installed_versions(fmt, bins)
    bins = [b for b in bins if b in before]
    if not bins:
        return "succes", "Paquets déjà retirés de la machine.", {"before": {}}
    data = {"before": before}
    if fmt == "deb":
        env = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
        code, out = run(["apt-get", "update", "-q"], env=env)
        lines.append(out[-2000:])
        code, out = run(["apt-get", "install", "-y", "-q", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold"] + bins, env=env)
    elif fmt == "rpm":
        code, out = run([dnf(), "-y", "upgrade"] + bins)
        c2, hist = run([dnf(), "history", "list"], timeout=60)
        m = re.search(r"^\s*(\d+)\s*\|", hist, re.M)
        if m:
            data["transaction"] = m.group(1)
    else:
        return "echec", "Gestionnaire de paquets non pris en charge.", {}
    lines.append(out[-6000:])
    after = installed_versions(fmt, bins)
    data["after"] = after
    data["rebootRequired"] = reboot_pending()
    if code != 0:
        return "echec", "\n".join(lines) + "\nCode de sortie %d" % code, data
    data["rebooting"] = do_reboot(payload.get("reboot", "aucun"), lines)
    changed = [b for b in bins if after.get(b) != before.get(b)]
    lines.append("Mis à jour : %s" % (", ".join("%s %s → %s" % (b, before.get(b), after.get(b)) for b in changed) or "aucun changement (déjà à jour ?)"))
    return "succes", "\n".join(lines), data


def job_rollback(payload):
    fmt = pkg_format()
    lines = []
    if fmt == "rpm" and payload.get("transaction"):
        if not re.match(r"^\d+$", str(payload["transaction"])):
            return "echec", "Transaction invalide.", {}
        code, out = run([dnf(), "-y", "history", "undo", str(payload["transaction"])])
    elif fmt == "deb" and payload.get("before"):
        pins = ["%s=%s" % (k, v) for k, v in sorted(payload["before"].items()) if re.match(r"^[A-Za-z0-9.+_-]+$", k) and re.match(r"^[A-Za-z0-9.+:~_-]+$", str(v))]
        if not pins:
            return "echec", "Aucune version précédente connue.", {}
        code, out = run(["apt-get", "install", "-y", "-q", "--allow-downgrades", "-o", "Dpkg::Options::=--force-confold"] + pins, env={"DEBIAN_FRONTEND": "noninteractive"})
    else:
        return "echec", "Rien à annuler pour cette installation.", {}
    lines.append(out[-6000:])
    if code != 0:
        return "echec", "\n".join(lines) + "\nCode de sortie %d (les versions précédentes ne sont peut-être plus disponibles dans les dépôts)" % code, {}
    do_reboot(payload.get("reboot", "aucun"), lines)
    return "succes", "\n".join(lines), {"rebootRequired": reboot_pending()}


def job_reboot(payload):
    lines = []
    if not payload.get("force") and not reboot_pending():
        return "succes", "Aucun redémarrage nécessaire.", {"rebooting": False}
    code, out = run(["shutdown", "-r", "+5", REBOOT_MESSAGE], timeout=30)
    lines.append(out[-500:])
    return ("succes" if code == 0 else "echec"), "\n".join(lines) or "Redémarrage programmé dans 5 minutes", {"rebooting": code == 0}


def execute(job, key):
    payload_json = job.get("payload", "{}")
    want = hmac.new(key.encode(), ("%s.%s.%s" % (job.get("id"), job.get("action"), payload_json)).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(job.get("sig", ""))):
        return {"id": job.get("id"), "status": "echec", "log": "Signature de la tâche invalide : tâche refusée."}
    try:
        payload = json.loads(payload_json)
        action = job.get("action")
        if action == "scan":
            status, out, data = "succes", "Inventaire envoyé.", {"inventory": True}
        elif action == "install":
            status, out, data = job_install(payload)
        elif action == "rollback":
            status, out, data = job_rollback(payload)
        elif action == "reboot":
            status, out, data = job_reboot(payload)
        else:
            status, out, data = "echec", "Action inconnue : refusée.", {}
    except Exception as e:  # noqa: BLE001 — l'agent ne doit jamais s'arrêter sur une tâche
        status, out, data = "echec", "Erreur de l'agent : %s" % e, {}
    return {"id": job.get("id"), "status": status, "log": out[-20000:], "data": data}


# ---------- Boucle ----------


def enroll(state):
    if not ENROLL_TOKEN.startswith("vqe_"):
        raise SystemExit("Jeton d'enrôlement absent : téléchargez l'installeur depuis la console VigilantIQ.")
    inv = inventory()
    code, r = http("POST", "/api/v1/agent/enroll", {"token": ENROLL_TOKEN, "machineId": machine_id(), "hostname": inv["hostname"], "os": inv["os"], "agentVersion": AGENT_VERSION})
    if code != 200 or not r.get("key"):
        raise SystemExit("Enrôlement refusé : %s" % r.get("error", code))
    state.update({"deviceId": r["deviceId"], "key": r["key"], "server": server_url(), "lastInventory": 0})
    save_state(state)
    log("Équipement enrôlé (n° %s)" % r["deviceId"])
    return state


def self_update(state, upd):
    script = upd.get("script", "")
    want = hmac.new(state["key"].encode(), ("script." + script).encode("utf-8"), hashlib.sha256).hexdigest()
    if not script or not hmac.compare_digest(want, str(upd.get("sig", ""))):
        log("Mise à jour de l'agent refusée : signature invalide")
        return False
    target = INSTALLED if os.path.exists(INSTALLED) else os.path.abspath(__file__)
    tmp = target + ".new"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(tmp, 0o700)
    os.replace(tmp, target)
    log("Agent mis à jour en version %s" % upd.get("version"))
    return True


def sync(state, results, force_inventory=False):
    body = {"agentVersion": AGENT_VERSION, "rebootPending": reboot_pending(), "results": results}
    due = time.time() - state.get("lastInventory", 0) > state.get("inventoryHours", 4) * 3600
    if force_inventory or due or state.get("wantInventory"):
        body["inventory"] = inventory()
    code, r = http("POST", "/api/v1/agent/sync", body, key=state["key"])
    if code == 401:
        raise PermissionError(r.get("error", "Clé refusée"))
    if code != 200:
        raise RuntimeError(r.get("error", "HTTP %d" % code))
    if "inventory" in body:
        state["lastInventory"] = time.time()
    state["wantInventory"] = bool(r.get("wantInventory"))
    state["inventoryHours"] = r.get("inventoryHours", 4)
    state["pollSeconds"] = r.get("pollSeconds", 60)
    save_state(state)
    return r


def cycle(state):
    """Une synchronisation, puis l'exécution des tâches reçues et le compte rendu immédiat."""
    r = sync(state, [])
    restart = False
    if r.get("update"):
        restart = self_update(state, r["update"])
    jobs = r.get("jobs", [])
    while jobs:
        results, inv = [], False
        for job in jobs:
            log("Tâche %s : %s" % (job.get("id"), job.get("action")))
            res = execute(job, state["key"])
            results.append(res)
            inv = inv or job.get("action") in ("scan", "install", "rollback")
        r = sync(state, results, force_inventory=inv)
        jobs = r.get("jobs", [])
    return restart


def main_loop():
    state = load_state()
    if not state.get("key"):
        state = enroll(state)
    backoff = 30
    while True:
        try:
            if cycle(state):
                os.execv(sys.executable, [sys.executable, INSTALLED if os.path.exists(INSTALLED) else os.path.abspath(__file__), "run"])
            backoff = 30
            time.sleep(max(15, int(state.get("pollSeconds", 60))))
        except PermissionError as e:
            log("Clé refusée par le serveur (%s) : équipement supprimé ou clé renouvelée. Réinstallez l'agent." % e)
            time.sleep(3600)
        except Exception as e:  # noqa: BLE001
            log("Synchronisation impossible : %s" % e)
            time.sleep(backoff)
            backoff = min(backoff * 2, 900)


def install():
    if os.geteuid() != 0:
        raise SystemExit("Lancez l'installation en root (sudo).")
    os.makedirs(INSTALL_DIR, mode=0o700, exist_ok=True)
    src = os.path.abspath(__file__)
    with open(src, "r", encoding="utf-8") as f:
        code = f.read()
    with open(INSTALLED, "w", encoding="utf-8") as f:
        f.write(code)
    os.chmod(INSTALLED, 0o700)
    state = load_state()
    if not state.get("key"):
        enroll(state)
    if shutil.which("systemctl") and os.path.isdir("/run/systemd/system"):
        with open(UNIT_FILE, "w", encoding="utf-8") as f:
            f.write(
                "[Unit]\nDescription=VigilantIQ - agent Parc et correctifs\nAfter=network-online.target\nWants=network-online.target\n\n"
                "[Service]\nType=simple\nExecStart=%s %s run\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=multi-user.target\n" % (sys.executable, INSTALLED)
            )
        run(["systemctl", "daemon-reload"], timeout=60)
        code, out = run(["systemctl", "enable", "--now", "vigilantiq-agent"], timeout=60)
        print("Service vigilantiq-agent installé et démarré." if code == 0 else "Service installé, démarrage impossible : " + out)
    else:
        with open(CRON_FILE, "w", encoding="utf-8") as f:
            f.write("* * * * * root %s %s once >/dev/null 2>&1\n" % (sys.executable, INSTALLED))
        print("systemd absent : synchronisation chaque minute via cron (%s)." % CRON_FILE)
    print("L'équipement apparaît dans la console VigilantIQ (Parc & correctifs).")


def uninstall():
    if os.geteuid() != 0:
        raise SystemExit("Lancez la désinstallation en root (sudo).")
    if os.path.exists(UNIT_FILE):
        run(["systemctl", "disable", "--now", "vigilantiq-agent"], timeout=60)
        os.remove(UNIT_FILE)
        run(["systemctl", "daemon-reload"], timeout=60)
    for p in (CRON_FILE, STATE_FILE, INSTALLED):
        if os.path.exists(p):
            os.remove(p)
    print("Agent désinstallé. Supprimez l'équipement dans la console pour effacer ses données.")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "install":
        install()
    elif cmd == "uninstall":
        uninstall()
    elif cmd == "once":
        state = load_state()
        if not state.get("key"):
            state = enroll(state)
        cycle(state)
    elif cmd == "status":
        s = load_state()
        print(json.dumps({"version": AGENT_VERSION, "enrolled": bool(s.get("key")), "deviceId": s.get("deviceId"), "server": s.get("server") or SERVER, "lastInventory": s.get("lastInventory")}, indent=2))
    elif cmd == "inventory":
        print(json.dumps(inventory(), indent=2, ensure_ascii=False)[:20000])
    elif cmd == "run":
        main_loop()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
