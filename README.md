# VigilantIQ

Application d'équipe qui rassemble en continu les nouvelles CVE et les alertes des CERT, éditeurs et bases d'exploits. Pour chaque vulnérabilité, elle donne :

- les **versions impactées** et les **versions corrigées** ;
- une **priorité** calculée et expliquée ;
- un **résumé en français** rédigé par IA ;
- les **références** (correctifs, avis éditeur, exploits) et les liens vers les **bases de vulnérabilités**.

## Comptes utilisateurs

Chaque personne a son compte. On peut le créer de deux façons :

- **E-mail et mot de passe**, avec un mot de passe de 10 caractères minimum ;
- **compte Google**.

L'application entière est réservée aux personnes connectées. Une base Postgres conserve, pour chaque utilisateur :

| Donnée | Usage |
|---|---|
| Profil | Nom, e-mail, adresse confirmée ou non, méthodes de connexion (mot de passe, Google) |
| Stack | Technologies suivies : vue « Ma stack », digest |
| Suivi des CVE | À traiter, en cours, traitée, non concernée. La vue « En cours » regroupe celles en cours |
| Digest | Activé ou non, priorité minimale, seulement ma stack |

**Sécurité :**
- Mots de passe hachés (scrypt).
- Sessions de 30 jours, révoquées immédiatement à la déconnexion, au changement de mot de passe et à la suppression du compte.
- Tentatives de connexion limitées.
- Inscription réservable à vos domaines via `ALLOWED_EMAIL_DOMAINS`.
- Le digest n'est envoyé qu'aux adresses confirmées. Les comptes Google sont confirmés d'office.

**Page « Mon compte » :**
- nom ;
- stack ;
- préférences de digest ;
- association du compte Google ;
- changement du mot de passe ;
- déconnexion de vos autres appareils ;
- suppression du compte, qui efface toutes ses données.

**Mot de passe oublié :** depuis la page de connexion, « Mot de passe oublié ? » envoie un lien valable une heure. Il permet de choisir un nouveau mot de passe et ferme les sessions ouvertes ailleurs. Il faut qu'un envoi d'e-mails soit configuré (voir ci-dessous) ; sinon le lien n'apparaît pas.

### Configurer l'envoi d'e-mails

Deux possibilités :

- **SMTP**, avec n'importe quelle boîte mail. Pour Gmail : activez la validation en deux étapes du compte, créez un mot de passe d'application sur https://myaccount.google.com/apppasswords, puis renseignez `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=465`, `SMTP_USER` (l'adresse Gmail) et `SMTP_PASS` (le mot de passe d'application, pas celui du compte). Gmail limite l'envoi à environ 500 e-mails par jour.
- **Resend** : `RESEND_API_KEY`. Sans domaine vérifié chez Resend, seuls les e-mails vers l'adresse du compte Resend partent.

`MAIL_FROM` change l'expéditeur affiché (facultatif).

### Activer la connexion Google

1. Dans Google Cloud Console, ouvrez « API et services », puis « Identifiants ». Créez un « ID client OAuth » de type « Application Web ».
2. Déclarez l'URI de redirection autorisée : `https://VOTRE-DOMAINE/api/auth/callback/google`.
3. Copiez l'identifiant et le secret dans `GOOGLE_CLIENT_ID` et `GOOGLE_CLIENT_SECRET`, puis redéployez. Le bouton « Continuer avec Google » apparaît.

## Sources

| Source | Ce qu'elle apporte | Fraîcheur |
|---|---|---|
| NVD API 2.0 | CVE publiées sur 24 h, CVSS, configurations CPE (plages de versions) | 3 h |
| CVE.org (CVE Services) | Fiche de l'éditeur (CNA) : produits et versions affectées/non affectées, références étiquetées, SSVC et CVSS de la CISA (ADP) | 6 h |
| OSV.dev | Paquets open source (PyPI, npm, Maven, Go…) : plages et version corrigée | 3 h |
| CISA KEV | Failles exploitées dans la nature, échéance de correction | 3 h |
| FIRST EPSS | Probabilité d'exploitation sous 30 jours | 3 h |
| Flux RSS | CERT-FR, CERT-EU, CISA, CERT/CC, Zero Day Initiative, Microsoft, Cisco, Fortinet, Palo Alto, Ubuntu, Exploit-DB, cvefeed.io | 2 à 3 min |

Les CVE citées par les flux sont extraites automatiquement. Une CVE signalée par un CERT mais absente de la fenêtre NVD est ajoutée au tableau à partir de sa fiche CVE.org.

## Priorité

Score de 0 à 100, déterministe et expliqué sur chaque fiche :

- CVSS : jusqu'à 60 points ;
- EPSS : jusqu'à 25 points ;
- exploitation active (KEV ou SSVC « active ») : +30, et rançongiciel : +5 ;
- code d'exploitation public (SSVC « poc » ou Exploit-DB) : +10 ;
- alerte d'un CERT ou d'une agence : +5.

Toute faille exploitée passe en « urgente ». L'IA rédige les explications, elle ne décide pas du score.

## Interface

- **Tableau** en trois colonnes : vues, liste, fiche. Vues disponibles : Aujourd'hui, Exploitées, Ma stack, Flux en direct.
- **Flux en direct :** vérifié toutes les minutes tant que l'onglet est ouvert, avec une pastille « N nouvelles alertes ». On peut filtrer par type de source, et toucher une CVE ouvre sa fiche.
- **Fiche :** versions impactées par source (éditeur, NVD, OSV), versions corrigées, plateformes, mentions dans les flux, références étiquetées, liens vers NVD, CVE.org, CISA KEV, OSV, GitHub Advisories, CIRCL Vulnerability-Lookup et Exploit-DB.
- **Page partageable** `/cve/CVE-AAAA-NNNN` pour n'importe quelle CVE, même hors du flux du jour.
- **Responsive :** trois colonnes sur ordinateur, panneau latéral sur tablette, feuille glissante sur téléphone. Mode sombre automatique, animations réduites si le système le demande.

## Coûts IA maîtrisés

Chaque résumé est mis en cache par CVE pendant 7 jours, ou jusqu'à ce que sa description change. La page peut se régénérer toutes les 3 minutes sans appel supplémentaire : on ne paie qu'une fois par vulnérabilité, puis seulement si sa description change.

## Fonctionnalités avancées

### Moniteur de PoC et d'exploits

Chaque matin à 6 h 30 (UTC), la tâche `/api/cron/veille` :

- cherche sur GitHub les dépôts créés dans les dernières 48 heures qui citent une CVE (les forks sont ignorés) ;
- consulte [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) pour chaque CVE à surveiller du jour ;
- reprend les exploits publiés sur Exploit-DB (flux RSS).

Les résultats sont enregistrés en base et partagés par l'équipe. Un PoC public ajoute 10 points au score de priorité. La vue « PoC publics » du tableau liste ces CVE et les dépôts détectés dans les 7 derniers jours. La fiche de chaque CVE affiche les dépôts, classés par crédibilité (Exploit-DB, puis nombre d'étoiles). Ces codes ne sont pas vérifiés : à n'exécuter que dans un environnement isolé.

`GITHUB_TOKEN` (facultatif, sans droit particulier) relève la limite de la recherche GitHub.

### Recommandations de correctifs et contournements

Chaque fiche contient un plan de remédiation en quatre volets : corriger, en attendant, détecter, vérifier.

- **Délai** : l'échéance CISA si la faille est au catalogue KEV ; sinon 48 heures (urgente), 7 jours (haute), 30 jours (moyenne) ou 90 jours (basse).
- **Correctif** : les versions corrigées, produit par produit (éditeur, NVD, OSV), la solution publiée par l'éditeur (champ « solutions » du format CVE JSON 5), les liens « correctif » et « avis éditeur », et l'action exigée par la CISA.
- **En attendant** : les contournements de l'éditeur (« workarounds »). S'il n'y en a pas, des mesures génériques sont proposées et marquées « VigilantIQ » : réduire l'exposition réseau, ou une mesure liée au type de faiblesse (CWE).
- **Détecter** : la recherche de compromission si la faille est exploitée, l'état des sauvegardes en cas de rançongiciel, une règle SIEM si un PoC circule.

Rien n'est inventé : chaque étape indique sa source. Quand l'API Claude est disponible, les consignes de l'éditeur sont traduites en français, avec un cache de 30 jours ; le texte d'origine reste consultable.

### API REST v1

Authentification par jeton (`Authorization: Bearer <jeton>` ou `X-API-Key: <jeton>`), à définir dans `VIGILANTIQ_API_TOKENS`, ou par la session d'un utilisateur connecté.

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/api/v1` | Index et état des connecteurs |
| GET | `/api/v1/vulns` | Vulnérabilités du jour. Filtres : `priority=urgente,haute`, `min_priority=haute`, `exploited=true`, `poc=true`, `stack=fortinet,nginx`, `q=texte`, `since=2026-10-27T00:00:00Z`, `limit=500` |
| GET | `/api/v1/vulns/{CVE}` | Fiche complète : versions, références, exploits, plan de remédiation, tickets |
| GET / POST | `/api/v1/vulns/{CVE}/tickets` | Tickets existants, ou création : `{"connector":"jira"}` (`servicenow`, `xsoar`, `siem`) |
| GET | `/api/v1/exploits` | PoC détectés (`days=7`) ou ceux d'une CVE (`cve=CVE-…`) |

Exemple : `curl -H "Authorization: Bearer $JETON" "https://vigilantiq.vercel.app/api/v1/vulns?min_priority=haute&exploited=true"`

### Connecteurs Jira, ServiceNow, Cortex XSOAR et SIEM

L'administrateur les configure une fois pour toute l'équipe, dans les variables d'environnement du projet (voir `.env.example`). Un connecteur s'active dès que ses variables obligatoires sont présentes.

- **Manuel** : sur chaque fiche, « Envoyer vers » crée le ticket ou l'incident. On peut aussi passer par l'API, par exemple depuis un playbook XSOAR.
- **Automatique** : chaque matin, les CVE dont la priorité est au moins `CONNECTORS_MIN_PRIORITY` (urgente par défaut) sont envoyées aux connecteurs listés dans `CONNECTORS_AUTO` (le SIEM par défaut). `CONNECTORS_STACK_ONLY=true` limite cet envoi à la stack de l'équipe.
- **Sans doublon** : une CVE ne crée qu'un ticket par outil, même en cas de double clic ou de passages répétés. Si l'outil ne répond pas, rien n'est enregistré et un nouvel essai reste possible.
- **Contenu en français** : priorité et score, CVSS, EPSS, exploitation, PoC, délai, versions impactées et corrigées, étapes de remédiation, liens vers la fiche, la NVD, l'avis de l'éditeur et les PoC.

| Outil | Variables obligatoires | Remarques |
|---|---|---|
| Jira Cloud | `JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | API v3, description au format ADF, étiquettes `vigilantiq`, `cve-…`, `priorite-…` |
| ServiceNow | `SERVICENOW_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` | Table `incident` par défaut ; impact et urgence selon la priorité ; `correlation_id = vigilantiq:CVE-…` |
| Cortex XSOAR | `XSOAR_URL`, `XSOAR_API_KEY` | XSOAR 8 : ajoutez `XSOAR_API_KEY_ID` ; sévérité 4 à 1 ; étiquettes CVE, Source et Priority |
| SIEM | `SIEM_URL` | `SIEM_FORMAT=splunk` (HEC), `elastic` (`_bulk`) ou `json` (webhook : Sentinel via Logic App, QRadar, Graylog…) |

« Mon compte » affiche l'état de chaque connecteur, sans jamais afficher de secret, ainsi qu'un bouton « Tester ». Ce bouton est réservé aux adresses listées dans `ADMIN_EMAILS` quand cette variable est définie.

## Points d'accès

| Chemin | Rôle |
|---|---|
| `/` | Tableau de veille |
| `/cve/[id]` | Fiche complète d'une CVE |
| `/api/cves` | Flux JSON du jour |
| `/api/cve/[id]` | Fiche JSON d'une CVE |
| `/api/rss` | Alertes des flux, avec CVE extraites |
| `/connexion`, `/mot-de-passe-oublie`, `/reinitialiser` | Inscription, connexion, mot de passe oublié |
| `/compte` | Profil, stack, digest, sécurité, suppression du compte |
| `/api/me` (+ `/settings`, `/status`) | Données de l'utilisateur connecté |
| `/api/auth/*` | Authentification (Better Auth) |
| `/api/digest` | Digest personnalisé par utilisateur + Slack d'équipe (cron 07:00 UTC, protégé par `CRON_SECRET`) |

## Déploiement sur Vercel

1. Importez le projet dans Vercel.
2. Ajoutez une base Postgres : onglet « Storage », puis « Neon », puis « Create ». `DATABASE_URL` est renseignée automatiquement.
3. Renseignez les variables d'environnement (voir `.env.example`) :
   - `BETTER_AUTH_SECRET` (`openssl rand -base64 32`) et `BETTER_AUTH_URL` ;
   - `ANTHROPIC_API_KEY` et `NVD_API_KEY` ;
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER` et `SMTP_PASS` (ou `RESEND_API_KEY`), et éventuellement `MAIL_FROM`, pour les e-mails ;
   - `GOOGLE_CLIENT_ID` et `GOOGLE_CLIENT_SECRET`, pour Google ;
   - `CRON_SECRET` ;
   - éventuellement `ALLOWED_EMAIL_DOMAINS`.
4. Déployez. La commande `npm run build` applique d'abord les migrations : les tables sont créées ou mises à jour automatiquement.

## Développement

```bash
npm install
cp .env.example .env.local
npm run db:migrate   # crée les tables dans la base de DATABASE_URL
npm run dev
npm test             # versions, références, RSS, score, filtrage
npm run db:generate  # après une modification de db/schema.ts
```

## Limites et prochaines étapes

- Le suivi des CVE est personnel. Étape suivante possible : des équipes, avec un suivi partagé et l'attribution d'une CVE à un collègue.
- Le « temps réel » est un sondage des flux toutes les 1 à 3 minutes : les éditeurs ne proposent pas de flux poussé.
- Certains flux peuvent changer d'adresse : leur état est visible dans « Sources ». Corrigez-les dans `lib/rss.ts` ou via `RSS_EXTRA_FEEDS` et `RSS_DISABLE`.
