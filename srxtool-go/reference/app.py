#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — petite interface web pour srxaudit.py / srxtool.py.

On dépose une conf SRX (peu importe le format : "show configuration | display
xml" OU un simple "show configuration" copié du CLI, la détection est
automatique — c'est srxaudit.py/srxtool.py qui s'en chargent), et la page
propose ensuite chaque document de sortie en téléchargement individuel :

  Audit de durcissement (srxaudit) :
    - rapport texte (.txt)
    - JSON (.json)
    - Excel coloré par sévérité (.xlsx)
    - correctifs set/delete (.set)

  Inventaire VLAN / zone / adresses / policies (srxtool inventory) :
    - rapport texte (.txt)
    - JSON (.json)
    - Excel (VLANs / Zones / Policies / Objets d'adresse) (.xlsx)

Dépendance : Flask uniquement (pip install flask). Toute la logique
d'analyse (srxaudit.py, srxtool.py) reste 100% stdlib.

Sécurité :
  - Authentification HTTP Basic obligatoire sur TOUTES les routes (y compris les
    téléchargements). Identifiants via SRXWEB_USER / SRXWEB_PASSWORD ; à défaut,
    un mot de passe aléatoire est généré et affiché au démarrage.
  - Chaque session de résultats est rattachée au compte qui l'a créée.
  - Les paramètres de téléchargement sont validés (sid par motif strict, nom de
    fichier par liste blanche, confinement sous le répertoire de sessions).
  - Il reste indispensable de placer le service derrière un reverse proxy TLS
    dès qu'il n'écoute plus uniquement sur 127.0.0.1 : l'auth Basic sans HTTPS
    transmet le mot de passe en base64 lisible sur le réseau.

Lancement :
    pip install flask
    SRXWEB_USER=moi SRXWEB_PASSWORD='...' python3 app.py
    -> http://127.0.0.1:5000
    (variables SRXWEB_HOST / SRXWEB_PORT pour changer l'écoute)
"""

import hmac
import os
import re
import secrets
import shutil
import sys
import tempfile
import time
import uuid

from flask import (Flask, Response, abort, redirect, render_template_string,
                    request, send_file, url_for)

import srxaudit
import srxtool

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 Mo, largement suffisant

BASE_DIR = os.path.join(tempfile.gettempdir(), "srxweb_sessions")
os.makedirs(BASE_DIR, exist_ok=True)
SESSION_TTL_SECONDS = 6 * 3600  # ménage best-effort des anciennes sessions

# --------------------------------------------------------------------------- #
# Authentification (HTTP Basic)
# --------------------------------------------------------------------------- #
# Ce service ingère des configurations de pare-feu et produit un rapport qui
# énumère leurs faiblesses exploitables : c'est un document d'attaque prêt à
# l'emploi. Il ne doit jamais être joignable sans authentification.
#
# Identifiants : variables d'environnement SRXWEB_USER / SRXWEB_PASSWORD.
# Si le mot de passe n'est pas fourni, on en génère un aléatoire au démarrage et
# on l'affiche sur la console — l'auth reste donc active en toutes circonstances
# (choix délibéré : pas de mode « sans authentification »).

AUTH_USER = os.environ.get("SRXWEB_USER", "admin")
AUTH_PASSWORD = os.environ.get("SRXWEB_PASSWORD") or None
_GENERATED_PASSWORD = False

if not AUTH_PASSWORD:
    AUTH_PASSWORD = secrets.token_urlsafe(18)
    _GENERATED_PASSWORD = True


def _check_auth(auth):
    if auth is None or not auth.username or auth.password is None:
        return False
    # compare_digest sur les deux champs : évite de fuiter le login par timing
    user_ok = hmac.compare_digest(auth.username, AUTH_USER)
    pass_ok = hmac.compare_digest(auth.password, AUTH_PASSWORD)
    return user_ok and pass_ok


def _auth_challenge():
    return Response(
        "Authentification requise.\n", 401,
        {"WWW-Authenticate": 'Basic realm="srxtool", charset="UTF-8"'})


@app.before_request
def _require_auth():
    """Protège TOUTES les routes, y compris /download — l'oubli classique est de
    n'authentifier que le formulaire et de laisser les fichiers accessibles."""
    if not _check_auth(request.authorization):
        return _auth_challenge()
    return None


def _current_user():
    auth = request.authorization
    return auth.username if auth else None


# --------------------------------------------------------------------------- #
# Validation des paramètres de téléchargement
# --------------------------------------------------------------------------- #
# os.path.basename() ne suffit PAS : basename("..") vaut "..", ce qui permettait
# de remonter d'un niveau et de télécharger n'importe quel fichier du répertoire
# temporaire (vérifié en HTTP avec /download/%2e%2e/<fichier>).
# On valide donc le sid par motif strict et le nom de fichier par liste blanche.

_SID_RE = re.compile(r"^[0-9a-f]{12,64}$")

DOWNLOADABLE_FILES = frozenset({
    "audit_report.txt", "audit.json", "audit.xlsx", "audit_fix.set",
    "inventory_report.txt", "inventory.json", "inventory.xlsx",
})

OWNER_FILE = ".owner"


def _cleanup_old_sessions():
    now = time.time()
    try:
        for name in os.listdir(BASE_DIR):
            p = os.path.join(BASE_DIR, name)
            try:
                if os.path.isdir(p) and (now - os.path.getmtime(p)) > SESSION_TTL_SECONDS:
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass
    except FileNotFoundError:
        pass


PAGE_HEAD = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>srxtool — audit &amp; inventaire SRX</title>
<style>
  :root { --navy:#2f3b52; --bg:#f4f6f9; --line:#dfe4ea; }
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         background: var(--bg); color:#1c2430; margin:0; }
  header { background: var(--navy); color:#fff; padding:22px 28px; }
  header h1 { margin:0; font-size:1.35rem; }
  header p { margin:6px 0 0; color:#c7ceda; font-size:0.92rem; }
  main { max-width:840px; margin:32px auto; padding:0 20px 60px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:10px;
          padding:26px 28px; margin-bottom:22px; }
  .card h2 { margin-top:0; font-size:1.1rem; }
  .drop { border:2px dashed #b7c0cd; border-radius:10px; padding:28px;
          text-align:center; color:#5a6472; }
  input[type=file] { margin-top:14px; }
  button, .btn { background: var(--navy); color:#fff; border:none;
         padding:11px 22px; border-radius:7px; font-size:0.95rem;
         cursor:pointer; text-decoration:none; display:inline-block; }
  button:hover, .btn:hover { background:#1f2a3d; }
  .btn.secondary { background:#fff; color:var(--navy); border:1px solid var(--navy); }
  table.files { width:100%; border-collapse:collapse; margin-top:6px; }
  table.files td { padding:9px 6px; border-bottom:1px solid var(--line); }
  table.files td:last-child { text-align:right; }
  .badge { display:inline-block; padding:3px 9px; border-radius:12px;
           font-size:0.78rem; font-weight:600; color:#fff; }
  .b-crit{background:#c00000}.b-high{background:#ff6b6b;color:#3a0000}
  .b-med{background:#ffd966;color:#4a3b00}.b-low{background:#7fae62}
  .b-info{background:#9aa4b1}
  .error { background:#fde8e8; border:1px solid #f3b4b4; color:#8a1f1f;
           padding:12px 16px; border-radius:8px; margin-bottom:18px; }
  .warn { background:#fff8e1; border:1px solid #f0d68a; color:#6b5200;
          padding:12px 16px; border-radius:8px; margin:14px 0; font-size:0.9rem; }
  .warn ul { margin:8px 0 0 18px; padding:0; }
  .muted { color:#6b7280; font-size:0.88rem; }
  .summary span { margin-right:14px; }
  footer { text-align:center; color:#8b93a1; font-size:0.82rem; margin-top:30px; }
</style>
</head>
<body>
<header>
  <h1>srxtool — audit de durcissement &amp; inventaire SRX</h1>
  <p>Dépose un "show configuration" (texte ou XML) — le format est détecté automatiquement.</p>
</header>
<main>
"""

PAGE_TAIL = """
<footer>Aucune donnée n'est envoyée vers l'extérieur — tout tourne en local sur ce serveur.
Fichiers de session nettoyés automatiquement après quelques heures.</footer>
</main>
</body>
</html>
"""

UPLOAD_FORM = PAGE_HEAD + """
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<div class="card">
  <h2>1. Déposer la configuration</h2>
  <form action="{{ url_for('analyze') }}" method="post" enctype="multipart/form-data">
    <div class="drop">
      Fichier "show configuration" (texte OU "display xml") — aucune limite de nom/extension.
      <div><input type="file" name="config" required></div>
    </div>
    <p class="muted">Sévérité minimum affichée dans le rapport texte de l'audit :</p>
    <select name="min_severity">
      <option value="INFO" selected>Tout afficher (INFO+)</option>
      <option value="LOW">LOW et plus</option>
      <option value="MEDIUM">MEDIUM et plus</option>
      <option value="HIGH">HIGH et plus</option>
      <option value="CRITICAL">CRITICAL uniquement</option>
    </select>
    <p><button type="submit">Analyser</button></p>
  </form>
</div>
""" + PAGE_TAIL

RESULTS_TMPL = PAGE_HEAD + """
<div class="card">
  <h2>Résultat de l'analyse</h2>
  <p class="muted">Session : {{ sid }} — {{ source_name }}
    {% if source_format %} — format détecté : <strong>{{ source_format }}</strong>{% endif %}
  </p>
  {% if audit_warnings %}
    <div class="warn">
      <strong>⚠ {{ audit_warnings|length }} avertissement(s) de lecture</strong> —
      une partie de la configuration n'a pas pu être interprétée, le résultat
      peut être incomplet :
      <ul>{% for w in audit_warnings %}<li>{{ w }}</li>{% endfor %}</ul>
    </div>
  {% endif %}
  {% if audit_error %}
    <div class="error">Audit de durcissement : {{ audit_error }}</div>
  {% else %}
    <h3>Audit de durcissement (srxaudit)</h3>
    <p class="summary">
      {% for sev, cnt in audit_counts %}
        <span class="badge b-{{ sev_class(sev) }}">{{ sev }} : {{ cnt }}</span>
      {% endfor %}
      &nbsp;— {{ audit_total }} constat(s) au total
    </p>
    <table class="files">
      <tr><td>Rapport texte (lisible)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='audit_report.txt') }}">Télécharger .txt</a></td></tr>
      <tr><td>Données structurées (JSON)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='audit.json') }}">Télécharger .json</a></td></tr>
      <tr><td>Tableau Excel coloré par sévérité</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='audit.xlsx') }}">Télécharger .xlsx</a></td></tr>
      <tr><td>Correctifs proposés (set/delete, à relire avant commit)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='audit_fix.set') }}">Télécharger .set</a></td></tr>
    </table>
  {% endif %}
</div>

<div class="card">
  {% if inv_error %}
    <div class="error">Inventaire VLAN/zone : {{ inv_error }}</div>
  {% else %}
    <h3>Inventaire VLAN / zone / adresses / policies (srxtool)</h3>
    <p class="muted">{{ inv_zones }} zone(s), {{ inv_vlans }} VLAN(s), {{ inv_policies }} policy(ies), {{ inv_addr }} objet(s) d'adresse.</p>
    <table class="files">
      <tr><td>Rapport texte (lisible)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='inventory_report.txt') }}">Télécharger .txt</a></td></tr>
      <tr><td>Données structurées (JSON)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='inventory.json') }}">Télécharger .json</a></td></tr>
      <tr><td>Classeur Excel (VLANs / Zones / Policies / Objets)</td>
          <td><a class="btn secondary" href="{{ url_for('download', sid=sid, fname='inventory.xlsx') }}">Télécharger .xlsx</a></td></tr>
    </table>
  {% endif %}
</div>

<p><a class="btn" href="{{ url_for('index') }}">&larr; Analyser une autre conf</a></p>
""" + PAGE_TAIL


def _sev_class(sev):
    return {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med",
            "LOW": "low", "INFO": "info"}.get(sev, "info")


@app.route("/", methods=["GET"])
def index():
    _cleanup_old_sessions()
    return render_template_string(UPLOAD_FORM, error=request.args.get("error"))


@app.route("/analyze", methods=["POST"])
def analyze():
    f = request.files.get("config")
    if not f or not f.filename:
        return redirect(url_for("index", error="Merci de sélectionner un fichier."))

    min_sev = request.form.get("min_severity", "INFO")
    if min_sev not in srxaudit.SEV_RANK:
        min_sev = "INFO"

    sid = uuid.uuid4().hex[:12]
    sess_dir = os.path.join(BASE_DIR, sid)
    os.makedirs(sess_dir, exist_ok=True)
    # rattache la session au compte qui l'a créée (vérifié au téléchargement)
    with open(os.path.join(sess_dir, OWNER_FILE), "w", encoding="utf-8") as fh:
        fh.write(_current_user() or "")
    conf_path = os.path.join(sess_dir, "config_input")
    f.save(conf_path)

    audit_error = inv_error = None
    audit_counts, audit_total = [], 0
    inv_zones = inv_vlans = inv_policies = inv_addr = 0
    audit_warnings, source_format = [], None
    format_error = None

    # --- audit de durcissement ---
    try:
        m, units, screens, zones, policies = srxaudit.parse(conf_path)
        findings = []
        srxaudit.check_policies(zones, policies, findings)
        srxaudit.check_zones(zones, screens, findings)
        if m["system"] is not None:
            srxaudit.check_system(m["system"], m["snmp"], findings)
        thr = srxaudit.SEV_RANK[min_sev]
        findings = [x for x in findings if srxaudit.SEV_RANK[x.sev] <= thr]
        findings.sort(key=lambda x: (srxaudit.SEV_RANK[x.sev], x.check, x.where))

        report_text = srxaudit.build_report_text(findings, meta=m)
        with open(os.path.join(sess_dir, "audit_report.txt"), "w", encoding="utf-8") as fh:
            fh.write(report_text + "\n")
        audit_warnings = list(m.get("warnings") or [])
        source_format = m.get("source_format")

        import json as _json
        with open(os.path.join(sess_dir, "audit.json"), "w", encoding="utf-8") as fh:
            _json.dump(srxaudit.build_findings_json(findings), fh, ensure_ascii=False, indent=2)

        srxaudit.export_findings_xlsx(findings, os.path.join(sess_dir, "audit.xlsx"))

        with open(os.path.join(sess_dir, "audit_fix.set"), "w", encoding="utf-8") as fh:
            fh.write(srxaudit.build_fix_text(findings))

        counts = srxaudit.count_by_severity(findings)
        audit_counts = [(s, counts.get(s, 0)) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                        if counts.get(s, 0)]
        audit_total = len(findings)
    except srxtool.ConfigFormatError as e:
        # format non reconnu / rien d'exploitable : message explicite, et on
        # n'affiche AUCUN résultat partiel qui pourrait passer pour un audit valide
        format_error = str(e)
        audit_error = str(e)
    except srxtool.UnsafeNameError as e:
        audit_error = (f"configuration refusée : {e}")
    except Exception as e:  # noqa: BLE001 - on affiche l'erreur, on ne casse pas l'autre analyse
        audit_error = f"{type(e).__name__}: {e}"

    # --- inventaire VLAN / zone ---
    try:
        model, zone_objects, address_objects, out = srxtool.build_inventory_model(conf_path)

        report_text = srxtool.build_inventory_report_text(model, zone_objects)
        with open(os.path.join(sess_dir, "inventory_report.txt"), "w", encoding="utf-8") as fh:
            fh.write(report_text + "\n")

        import json as _json
        with open(os.path.join(sess_dir, "inventory.json"), "w", encoding="utf-8") as fh:
            _json.dump(out, fh, ensure_ascii=False, indent=2)

        srxtool.export_inventory_xlsx(model, zone_objects, os.path.join(sess_dir, "inventory.xlsx"))

        inv_zones = len(model["zones"])
        inv_vlans = len(model["vlans"])
        inv_policies = len(model["policies"])
        inv_addr = len(address_objects)
    except srxtool.ConfigFormatError as e:
        format_error = str(e)
        inv_error = str(e)
    except Exception as e:  # noqa: BLE001
        inv_error = f"{type(e).__name__}: {e}"

    if audit_error and inv_error:
        shutil.rmtree(sess_dir, ignore_errors=True)
        # Format non reconnu : on renvoie le message explicite du parseur plutôt
        # qu'une page de résultats vide qui laisserait croire à une conf saine.
        msg = format_error or (
            "Impossible d'analyser ce fichier. Vérifie qu'il s'agit bien d'un "
            "'show configuration', d'un '| display set' ou d'un '| display xml'.")
        return redirect(url_for("index", error=msg))

    return render_template_string(
        RESULTS_TMPL, sid=sid, source_name=f.filename,
        audit_error=audit_error, audit_counts=audit_counts, audit_total=audit_total,
        inv_error=inv_error, inv_zones=inv_zones, inv_vlans=inv_vlans,
        inv_policies=inv_policies, inv_addr=inv_addr, sev_class=_sev_class,
        audit_warnings=audit_warnings, source_format=source_format)


@app.route("/download/<sid>/<fname>")
def download(sid, fname):
    # 1) sid : motif strict (hexadécimal). Refuse '..', '.', chemins encodés, etc.
    if not _SID_RE.match(sid or ""):
        abort(404)
    # 2) nom de fichier : liste blanche, pas de nom arbitraire
    if fname not in DOWNLOADABLE_FILES:
        abort(404)

    sess_dir = os.path.join(BASE_DIR, sid)
    path = os.path.join(sess_dir, fname)

    # 3) ceinture et bretelles : le chemin résolu doit rester sous BASE_DIR
    base_real = os.path.realpath(BASE_DIR)
    path_real = os.path.realpath(path)
    if not path_real.startswith(base_real + os.sep):
        abort(404)

    if not os.path.isfile(path_real):
        abort(404)

    # 4) cloisonnement : on ne sert que les sessions créées par le même compte
    owner_path = os.path.join(sess_dir, OWNER_FILE)
    try:
        with open(owner_path, encoding="utf-8") as fh:
            owner = fh.read().strip()
    except OSError:
        owner = None
    if owner is not None and owner != _current_user():
        abort(404)

    return send_file(path_real, as_attachment=True, download_name=fname)


def _startup_banner(host, port):
    print("=" * 68)
    print("  srxtool web — audit & inventaire SRX")
    print("=" * 68)
    print(f"  URL       : http://{host}:{port}")
    print(f"  Utilisateur : {AUTH_USER}")
    if _GENERATED_PASSWORD:
        print(f"  Mot de passe (généré pour cette exécution) : {AUTH_PASSWORD}")
        print("  -> Pour le fixer : SRXWEB_USER / SRXWEB_PASSWORD dans "
              "l'environnement.")
    else:
        print("  Mot de passe : (fourni via SRXWEB_PASSWORD)")
    if host not in ("127.0.0.1", "localhost"):
        print()
        print("  ⚠ Ce service est exposé au-delà de la machine locale.")
        print("    Les configurations et rapports transitent EN CLAIR : place-le")
        print("    derrière un reverse proxy TLS. L'auth Basic sans HTTPS envoie")
        print("    le mot de passe en base64 lisible sur le réseau.")
    print("=" * 68)


if __name__ == "__main__":
    host = os.environ.get("SRXWEB_HOST", "127.0.0.1")
    port = int(os.environ.get("SRXWEB_PORT", "5000"))
    _startup_banner(host, port)
    app.run(host=host, port=port, debug=False)
