import { boolean, index, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

// ---------- Tables de Better Auth (comptes, sessions, connexions Google, jetons) ----------

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  /** Double authentification (TOTP) activée */
  twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/**
 * Secret TOTP et codes de secours (plugin twoFactor de Better Auth). Les deux sont chiffrés avec le secret
 * de l'application ; les tentatives ratées sont comptées et le compte est temporairement bloqué après abus.
 */
export const twoFactor = pgTable(
  "two_factor",
  {
    id: text("id").primaryKey(),
    secret: text("secret").notNull(),
    backupCodes: text("backup_codes").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    verified: boolean("verified").notNull().default(true),
    failedVerificationCount: integer("failed_verification_count").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),
  },
  (t) => [index("two_factor_user_idx").on(t.userId), index("two_factor_secret_idx").on(t.secret)],
);

export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    token: text("token").notNull().unique(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
  },
  (t) => [index("session_user_idx").on(t.userId)],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at", { withTimezone: true }),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at", { withTimezone: true }),
    scope: text("scope"),
    password: text("password"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("account_user_idx").on(t.userId)],
);

export const verification = pgTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("verification_identifier_idx").on(t.identifier)],
);

// ---------- Données de l'application, par utilisateur ----------

/** Préférences : technologies suivies et digest quotidien. */
export const userSettings = pgTable("user_settings", {
  userId: text("user_id")
    .primaryKey()
    .references(() => user.id, { onDelete: "cascade" }),
  stack: text("stack").notNull().default(""),
  digestEnabled: boolean("digest_enabled").notNull().default(true),
  /** urgente | haute | moyenne : priorité minimale incluse dans le digest */
  digestMinPriority: text("digest_min_priority").notNull().default("haute"),
  /** true : seulement les CVE de la stack (les urgentes exploitées restent toujours incluses) */
  digestStackOnly: boolean("digest_stack_only").notNull().default(false),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Suivi de chaque CVE par l'utilisateur. Absence de ligne = « à traiter ». */
export const cveStatus = pgTable(
  "cve_status",
  {
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    /** en_cours | traitee | non_concernee */
    status: text("status").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.cveId] })],
);

// ---------- Données partagées par l'équipe ----------

/** Codes d'exploitation et PoC publics détectés (dépôts GitHub, Exploit-DB…). Un lien = une ligne. */
export const exploit = pgTable(
  "exploit",
  {
    url: text("url").primaryKey(),
    cveId: text("cve_id").notNull(),
    /** github | exploitdb */
    source: text("source").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull().default(""),
    stars: integer("stars").notNull().default(0),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("exploit_cve_idx").on(t.cveId), index("exploit_first_seen_idx").on(t.firstSeen)],
);

/** Tickets ou incidents créés dans les outils de l'équipe (Jira, ServiceNow, XSOAR) et envois au SIEM. */
export const ticket = pgTable(
  "ticket",
  {
    cveId: text("cve_id").notNull(),
    /** jira | servicenow | xsoar | siem */
    connector: text("connector").notNull(),
    externalId: text("external_id").notNull().default(""),
    url: text("url").notNull().default(""),
    /** null = envoi automatique */
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("ticket_cve_connector_idx").on(t.cveId, t.connector)],
);

// ---------- Renseignement sur les menaces (par utilisateur) ----------

/** Liste de surveillance : domaines et marques à rechercher dans les fuites, les sites de rançongiciels, l'hameçonnage… */
export const watchItem = pgTable(
  "watch_item",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** domain | brand */
    kind: text("kind").notNull(),
    value: text("value").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
    /** Jeton à publier en enregistrement DNS TXT pour prouver la propriété du domaine */
    verifyToken: text("verify_token"),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("watch_item_user_value_idx").on(t.userId, t.kind, t.value)],
);

/**
 * Comptes (adresses e-mail) d'un domaine vérifié, contrôlés dans les fuites et les infections par infostealer.
 * On ne stocke que des métadonnées : jamais de mot de passe, d'identifiant ni d'adresse IP.
 */
export const watchAccount = pgTable(
  "watch_account",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    email: text("email").notNull(),
    /** pending | clean | exposed | error */
    status: text("status").notNull().default("pending"),
    breaches: jsonb("breaches").$type<Record<string, unknown>[]>().notNull().default([]),
    stealers: jsonb("stealers").$type<Record<string, unknown>[]>().notNull().default([]),
    error: text("error"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    checkedAt: timestamp("checked_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("watch_account_user_email_idx").on(t.userId, t.email), index("watch_account_checked_idx").on(t.checkedAt)],
);

/** Alertes de renseignement : une détection = une ligne (dédoublonnée par source et identifiant externe). */
export const ctiAlert = pgTable(
  "cti_alert",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** ransomware | infostealer | breach | typosquat | phishing | email */
    source: text("source").notNull(),
    externalId: text("external_id").notNull(),
    watchValue: text("watch_value").notNull().default(""),
    /** critique | haute | moyenne | info */
    severity: text("severity").notNull().default("moyenne"),
    title: text("title").notNull(),
    detail: jsonb("detail").$type<Record<string, unknown>>().notNull().default({}),
    url: text("url").notNull().default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    seenAt: timestamp("seen_at", { withTimezone: true }),
    notifiedAt: timestamp("notified_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("cti_alert_dedup_idx").on(t.userId, t.source, t.externalId), index("cti_alert_user_created_idx").on(t.userId, t.createdAt)],
);

// ---------- Fuites détectées sur les forums du darkweb (collecte externe → ingestion → corrélation) ----------

/**
 * Source d'événements de fuite : fournisseur, partenaire, instance MISP/TAXII ou saisie analyste.
 * Aucun secret n'est stocké : la clé d'ingestion est dérivée (HMAC du secret serveur et du sel) et montrée une seule fois.
 */
export const leakSource = pgTable("leak_source", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  /** forum | marketplace | telegram | paste | stealer | provider | misp | taxii | manual */
  kind: text("kind").notNull(),
  /** Fiabilité de la source, code de l'Amirauté : A (sûre) à F (inconnue) */
  reliability: text("reliability").notNull().default("F"),
  language: text("language").notNull().default(""),
  keySalt: text("key_salt"),
  active: boolean("active").notNull().default(true),
  createdBy: text("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastIngestAt: timestamp("last_ingest_at", { withTimezone: true }),
});

/** File d'ingestion : charge déjà minimisée (aucun secret, identifiants hachés), vidée après traitement. */
export const ingestJob = pgTable(
  "ingest_job",
  {
    id: serial("id").primaryKey(),
    sourceId: integer("source_id")
      .notNull()
      .references(() => leakSource.id, { onDelete: "cascade" }),
    idempotencyKey: text("idempotency_key").notNull(),
    payload: jsonb("payload").$type<Record<string, unknown> | null>(),
    /** queued | done | error */
    status: text("status").notNull().default("queued"),
    attempts: integer("attempts").notNull().default(0),
    error: text("error"),
    result: jsonb("result").$type<Record<string, unknown> | null>(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    processedAt: timestamp("processed_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("ingest_job_idem_idx").on(t.sourceId, t.idempotencyKey), index("ingest_job_status_idx").on(t.status, t.createdAt)],
);

/** Événement de fuite (annonce sur un forum, dépôt, message Telegram…), dédoublonné par empreinte de preuve. */
export const leakEvent = pgTable(
  "leak_event",
  {
    id: serial("id").primaryKey(),
    sourceId: integer("source_id")
      .notNull()
      .references(() => leakSource.id, { onDelete: "cascade" }),
    externalId: text("external_id"),
    evidenceHash: text("evidence_hash").notNull(),
    title: text("title").notNull(),
    actor: text("actor").notNull().default(""),
    victim: text("victim").notNull().default(""),
    victimDomain: text("victim_domain"),
    postedAt: timestamp("posted_at", { withTimezone: true }),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull().defaultNow(),
    /** Volume annoncé (nombre d'enregistrements) */
    volume: integer("volume"),
    /** credentials | passwords | cookies | pii | financial | documents | emails | other */
    dataClasses: jsonb("data_classes").$type<string[]>().notNull().default([]),
    price: text("price").notNull().default(""),
    /** Référence d'origine (lien, identifiant de message) : visible des seuls analystes */
    reference: text("reference").notNull().default(""),
    /** claimed | sample_verified | confirmed | false_positive */
    status: text("status").notNull().default("claimed"),
    /** Fiabilité retenue par l'analyste (sinon celle de la source) */
    reliability: text("reliability"),
    analystNote: text("analyst_note").notNull().default(""),
    qualifiedBy: text("qualified_by"),
    qualifiedAt: timestamp("qualified_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("leak_event_evidence_idx").on(t.evidenceHash), index("leak_event_observed_idx").on(t.observedAt), index("leak_event_status_idx").on(t.status)],
);

/** Identifiant exposé : jamais en clair (empreinte HMAC + forme masquée), seulement des indicateurs de présence pour les secrets. */
export const leakIndicator = pgTable(
  "leak_indicator",
  {
    id: serial("id").primaryKey(),
    eventId: integer("event_id")
      .notNull()
      .references(() => leakEvent.id, { onDelete: "cascade" }),
    /** domain | email | username | ip */
    kind: text("kind").notNull(),
    /** Domaine rattaché (en clair : sert à la corrélation) */
    domain: text("domain"),
    valueHash: text("value_hash").notNull(),
    masked: text("masked").notNull(),
    hasPassword: boolean("has_password").notNull().default(false),
    hasCookie: boolean("has_cookie").notNull().default(false),
    hasPii: boolean("has_pii").notNull().default(false),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("leak_indicator_event_hash_idx").on(t.eventId, t.valueHash), index("leak_indicator_domain_idx").on(t.domain), index("leak_indicator_hash_idx").on(t.valueHash)],
);

/** Rapprochement d'un événement avec un élément surveillé d'un utilisateur. */
export const leakMatch = pgTable(
  "leak_match",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    watchItemId: integer("watch_item_id")
      .notNull()
      .references(() => watchItem.id, { onDelete: "cascade" }),
    eventId: integer("event_id")
      .notNull()
      .references(() => leakEvent.id, { onDelete: "cascade" }),
    /** domain | subdomain | account | brand | typosquat */
    mode: text("mode").notNull(),
    /** Identifiants concernés pour cet utilisateur */
    indicatorCount: integer("indicator_count").notNull().default(0),
    score: integer("score").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("leak_match_dedup_idx").on(t.userId, t.watchItemId, t.eventId), index("leak_match_user_idx").on(t.userId, t.updatedAt)],
);

// ---------- Threat Hunting : équipements, observables, détections, enquêtes IA ----------

/** Équipement surveillé (poste, serveur…), alimenté par l'agent collecteur ou le connecteur SIEM/EDR. */
export const huntAsset = pgTable(
  "hunt_asset",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /** poste | serveur | reseau | cloud | autre */
    kind: text("kind").notNull().default("poste"),
    /** agent | siem */
    source: text("source").notNull().default("agent"),
    hostname: text("hostname"),
    os: text("os").notNull().default(""),
    lastIp: text("last_ip"),
    /** Sel de la clé de l'agent (la clé elle-même n'est jamais stockée) */
    keySalt: text("key_salt"),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("hunt_asset_user_name_idx").on(t.userId, t.name)],
);

/** Observable vu sur un équipement (adresse IP distante, domaine, URL, empreinte d'exécutable), dédoublonné. */
export const huntObservation = pgTable(
  "hunt_observation",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    assetId: integer("asset_id")
      .notNull()
      .references(() => huntAsset.id, { onDelete: "cascade" }),
    /** ip | domain | url | sha256 | sha1 | md5 */
    kind: text("kind").notNull(),
    value: text("value").notNull(),
    /** Contexte le plus récent : processus, port, chemin, octets envoyés… */
    context: jsonb("context").$type<Record<string, unknown>>().notNull().default({}),
    count: integer("count").notNull().default(1),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("hunt_obs_asset_kind_value_idx").on(t.assetId, t.kind, t.value), index("hunt_obs_user_kind_value_idx").on(t.userId, t.kind, t.value), index("hunt_obs_last_seen_idx").on(t.lastSeen)],
);

/** Détection : trace de compromission (IOC), exfiltration, tunnel, domaine ressemblant, fuite. */
export const huntFinding = pgTable(
  "hunt_finding",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    assetId: integer("asset_id").references(() => huntAsset.id, { onDelete: "cascade" }),
    /** ioc | exfiltration | tunnel_dns | tor | ressemblant | fuite */
    kind: text("kind").notNull(),
    indicatorType: text("indicator_type").notNull(),
    indicator: text("indicator").notNull(),
    source: text("source").notNull(),
    threat: text("threat").notNull().default(""),
    malware: text("malware").notNull().default(""),
    /** critique | haute | moyenne | info */
    severity: text("severity").notNull().default("moyenne"),
    confidence: integer("confidence"),
    evidence: jsonb("evidence").$type<Record<string, unknown>>().notNull().default({}),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
    /** nouveau | en_cours | resolu | faux_positif */
    status: text("status").notNull().default("nouveau"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("hunt_finding_dedup_idx").on(t.userId, t.assetId, t.kind, t.indicator), index("hunt_finding_user_idx").on(t.userId, t.status, t.lastSeen)],
);

/** Connecteur SIEM/EDR d'un utilisateur ; les identifiants sont chiffrés (AES-256-GCM). */
export const huntSiem = pgTable("hunt_siem", {
  userId: text("user_id")
    .primaryKey()
    .references(() => user.id, { onDelete: "cascade" }),
  /** elastic (Elastic, OpenSearch, Wazuh) | splunk */
  type: text("type").notNull(),
  url: text("url").notNull(),
  index: text("index").notNull().default(""),
  authEnc: text("auth_enc").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  lastPullAt: timestamp("last_pull_at", { withTimezone: true }),
  lastError: text("last_error"),
  lastStats: jsonb("last_stats").$type<Record<string, unknown>>(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Chasse ou enquête de l'agent IA : statistiques et rapport. */
export const huntRun = pgTable(
  "hunt_run",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** chasse | enquete */
    kind: text("kind").notNull(),
    trigger: text("trigger").notNull().default("manuel"),
    stats: jsonb("stats").$type<Record<string, unknown>>().notNull().default({}),
    report: text("report"),
    model: text("model"),
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("hunt_run_user_idx").on(t.userId, t.startedAt)],
);

export const schema = { user, session, account, verification, twoFactor, userSettings, cveStatus, exploit, ticket, watchItem, watchAccount, ctiAlert, leakSource, ingestJob, leakEvent, leakIndicator, leakMatch, huntAsset, huntObservation, huntFinding, huntSiem, huntRun };
