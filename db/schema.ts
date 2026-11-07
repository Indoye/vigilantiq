import { boolean, index, integer, jsonb, pgTable, primaryKey, real, serial, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

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
// ---------- Organisations (locataires) : chaque donnée métier appartient à une organisation ----------

export const organization = pgTable("organization", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Appartenance : un compte appartient à une seule organisation. owner | admin | analyst | viewer */
export const orgMember = pgTable(
  "org_member",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role").notNull().default("viewer"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("org_member_user_idx").on(t.userId), index("org_member_org_idx").on(t.orgId)],
);

/** Invitation par e-mail : seule l'empreinte du jeton est stockée. */
export const orgInvite = pgTable(
  "org_invite",
  {
    id: text("id").primaryKey(),
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    role: text("role").notNull().default("analyst"),
    tokenHash: text("token_hash").notNull(),
    invitedBy: text("invited_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("org_invite_token_idx").on(t.tokenHash), index("org_invite_email_idx").on(t.email)],
);

/** Réglages partagés de l'organisation (stack technique). */
export const orgSettings = pgTable("org_settings", {
  orgId: text("org_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  stack: text("stack").notNull().default(""),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Connecteur d'une organisation (Jira, ServiceNow, XSOAR, SIEM, MISP, TAXII) : configuration chiffrée (AES-256-GCM). */
export const orgConnector = pgTable(
  "org_connector",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    configEnc: text("config_enc").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    /** Envoi automatique des CVE prioritaires (connecteurs de tickets) */
    autoSend: boolean("auto_send").notNull().default(false),
    lastError: text("last_error"),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.type] })],
);

/** Clé d'API d'une organisation : seule l'empreinte SHA-256 est stockée. */
export const orgApiKey = pgTable(
  "org_api_key",
  {
    id: serial("id").primaryKey(),
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    prefix: text("prefix").notNull(),
    keyHash: text("key_hash").notNull(),
    /** lecture | ecriture */
    scope: text("scope").notNull().default("lecture"),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("org_api_key_hash_idx").on(t.keyHash), index("org_api_key_org_idx").on(t.orgId)],
);

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
  digestEnabled: boolean("digest_enabled").notNull().default(true),
  /** urgente | haute | moyenne : priorité minimale incluse dans le digest */
  digestMinPriority: text("digest_min_priority").notNull().default("haute"),
  /** true : seulement les CVE de la stack (les urgentes exploitées restent toujours incluses) */
  digestStackOnly: boolean("digest_stack_only").notNull().default(false),
  /** Carte « Bien démarrer » masquée par l'utilisateur */
  onboardingHidden: boolean("onboarding_hidden").notNull().default(false),
  /** Dernière ouverture du centre de notifications */
  notificationsSeenAt: timestamp("notifications_seen_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Suivi de chaque CVE par l'utilisateur. Absence de ligne = « à traiter ». */
export const cveStatus = pgTable(
  "cve_status",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    /** en_cours | traitee | non_concernee */
    status: text("status").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.cveId] })],
);

/** Passkeys (WebAuthn) : connexion par Face ID, Touch ID, Windows Hello ou clé de sécurité. */
export const passkey = pgTable(
  "passkey",
  {
    id: text("id").primaryKey(),
    name: text("name"),
    publicKey: text("public_key").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    credentialID: text("credential_id").notNull(),
    counter: integer("counter").notNull(),
    deviceType: text("device_type").notNull(),
    backedUp: boolean("backed_up").notNull(),
    transports: text("transports"),
    createdAt: timestamp("created_at", { withTimezone: true }),
    aaguid: text("aaguid"),
  },
  (t) => [index("passkey_user_idx").on(t.userId), index("passkey_credential_idx").on(t.credentialID)],
);

/** Avis des utilisateurs (bouton « Donner mon avis »). */
export const feedback = pgTable(
  "feedback",
  {
    id: serial("id").primaryKey(),
    userId: text("user_id").references(() => user.id, { onDelete: "set null" }),
    orgId: text("org_id"),
    /** content | neutre | mecontent */
    mood: text("mood").notNull(),
    message: text("message").notNull().default(""),
    page: text("page").notNull().default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("feedback_created_idx").on(t.createdAt)],
);

/** Responsable d'une CVE dans l'organisation (une personne à la fois). */
export const cveAssignment = pgTable(
  "cve_assignment",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    assigneeId: text("assignee_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    assignedBy: text("assigned_by"),
    assignedAt: timestamp("assigned_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.cveId] }), index("cve_assignment_user_idx").on(t.assigneeId)],
);

/** Fil de discussion de l'équipe sur une CVE. */
export const cveComment = pgTable(
  "cve_comment",
  {
    id: serial("id").primaryKey(),
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    userId: text("user_id").references(() => user.id, { onDelete: "set null" }),
    body: text("body").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("cve_comment_org_cve_idx").on(t.orgId, t.cveId, t.createdAt)],
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
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    /** jira | servicenow | xsoar | siem */
    connector: text("connector").notNull(),
    externalId: text("external_id").notNull().default(""),
    url: text("url").notNull().default(""),
    /** null = envoi automatique */
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("ticket_org_cve_connector_idx").on(t.orgId, t.cveId, t.connector)],
);

// ---------- Renseignement sur les menaces (par utilisateur) ----------

/** Liste de surveillance : domaines et marques à rechercher dans les fuites, les sites de rançongiciels, l'hameçonnage… */
export const watchItem = pgTable(
  "watch_item",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    /** domain | brand */
    kind: text("kind").notNull(),
    value: text("value").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
    /** Jeton à publier en enregistrement DNS TXT pour prouver la propriété du domaine */
    verifyToken: text("verify_token"),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("watch_item_org_value_idx").on(t.orgId, t.kind, t.value)],
);

/**
 * Comptes (adresses e-mail) d'un domaine vérifié, contrôlés dans les fuites et les infections par infostealer.
 * On ne stocke que des métadonnées : jamais de mot de passe, d'identifiant ni d'adresse IP.
 */
export const watchAccount = pgTable(
  "watch_account",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("watch_account_org_email_idx").on(t.orgId, t.email), index("watch_account_checked_idx").on(t.checkedAt)],
);

/** Alertes de renseignement : une détection = une ligne (dédoublonnée par source et identifiant externe). */
export const ctiAlert = pgTable(
  "cti_alert",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("cti_alert_dedup_idx").on(t.orgId, t.source, t.externalId), index("cti_alert_org_created_idx").on(t.orgId, t.createdAt)],
);

// ---------- Fuites détectées sur les forums du darkweb (collecte externe → ingestion → corrélation) ----------

/**
 * Source d'événements de fuite : fournisseur, partenaire, instance MISP/TAXII ou saisie analyste.
 * Aucun secret n'est stocké : la clé d'ingestion est dérivée (HMAC du secret serveur et du sel) et montrée une seule fois.
 */
export const leakSource = pgTable("leak_source", {
  orgId: text("org_id").references(() => organization.id, { onDelete: "cascade" }),
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
    orgId: text("org_id").references(() => organization.id, { onDelete: "cascade" }),
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
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("leak_match_dedup_idx").on(t.orgId, t.watchItemId, t.eventId), index("leak_match_org_idx").on(t.orgId, t.updatedAt)],
);

// ---------- Threat Hunting : équipements, observables, détections, enquêtes IA ----------

/** Équipement surveillé (poste, serveur…), alimenté par l'agent collecteur ou le connecteur SIEM/EDR. */
export const huntAsset = pgTable(
  "hunt_asset",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("hunt_asset_org_name_idx").on(t.orgId, t.name)],
);

/** Observable vu sur un équipement (adresse IP distante, domaine, URL, empreinte d'exécutable), dédoublonné. */
export const huntObservation = pgTable(
  "hunt_observation",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("hunt_obs_asset_kind_value_idx").on(t.assetId, t.kind, t.value), index("hunt_obs_org_kind_value_idx").on(t.orgId, t.kind, t.value), index("hunt_obs_last_seen_idx").on(t.lastSeen)],
);

/** Détection : trace de compromission (IOC), exfiltration, tunnel, domaine ressemblant, fuite. */
export const huntFinding = pgTable(
  "hunt_finding",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [uniqueIndex("hunt_finding_dedup_idx").on(t.orgId, t.assetId, t.kind, t.indicator), index("hunt_finding_org_idx").on(t.orgId, t.status, t.lastSeen)],
);

/** Connecteur SIEM/EDR d'un utilisateur ; les identifiants sont chiffrés (AES-256-GCM). */
export const huntSiem = pgTable("hunt_siem", {
  orgId: text("org_id")
    .notNull()
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
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
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
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
  (t) => [index("hunt_run_org_idx").on(t.orgId, t.startedAt)],
);

// ---------- Parc & correctifs : agent local, inventaire, CVE par équipement, déploiement des correctifs ----------

/** Jeton d'enrôlement d'un utilisateur : intégré à l'installeur de l'agent. Seul le sel est stocké. */
export const patchEnroll = pgTable("patch_enroll", {
  orgId: text("org_id")
    .notNull()
    .unique()
    .references(() => organization.id, { onDelete: "cascade" }),
  id: serial("id").primaryKey(),
  keySalt: text("key_salt").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Équipement enrôlé par l'agent (poste ou serveur). La clé de l'équipement n'est jamais stockée, seulement son sel. */
export const patchDevice = pgTable(
  "patch_device",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    /** Identifiant stable de la machine, calculé par l'agent */
    machineId: text("machine_id").notNull(),
    name: text("name").notNull(),
    hostname: text("hostname").notNull().default(""),
    /** poste | serveur */
    kind: text("kind").notNull().default("poste"),
    /** windows | linux */
    osFamily: text("os_family").notNull(),
    osName: text("os_name").notNull().default(""),
    osVersion: text("os_version").notNull().default(""),
    arch: text("arch").notNull().default(""),
    ip: text("ip"),
    domain: text("domain").notNull().default(""),
    loggedUser: text("logged_user").notNull().default(""),
    groupName: text("group_name").notNull().default(""),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
    /** pilote | production */
    ring: text("ring").notNull().default("production"),
    hardware: jsonb("hardware").$type<Record<string, string>>().notNull().default({}),
    keySalt: text("key_salt"),
    agentVersion: text("agent_version").notNull().default(""),
    /** Gestionnaire de paquets d'applications disponible (winget) */
    appManager: boolean("app_manager").notNull().default(false),
    rebootPending: boolean("reboot_pending").notNull().default(false),
    inventoryRequested: boolean("inventory_requested").notNull().default(true),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    lastInventoryAt: timestamp("last_inventory_at", { withTimezone: true }),
    correlatedAt: timestamp("correlated_at", { withTimezone: true }),
    correlateError: text("correlate_error"),
    enrolledAt: timestamp("enrolled_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("patch_device_machine_idx").on(t.orgId, t.machineId), index("patch_device_org_idx").on(t.orgId, t.lastSeenAt)],
);

/** Composant inventorié : système, mise à jour installée, application, paquet, pilote, BIOS. Remplacé à chaque inventaire. */
export const patchComponent = pgTable(
  "patch_component",
  {
    id: serial("id").primaryKey(),
    deviceId: integer("device_id")
      .notNull()
      .references(() => patchDevice.id, { onDelete: "cascade" }),
    /** os | kb | app | package | driver | bios | hardware */
    kind: text("kind").notNull(),
    name: text("name").notNull(),
    vendor: text("vendor").notNull().default(""),
    version: text("version").notNull().default(""),
    /** Paquet source (Linux) */
    source: text("source").notNull().default(""),
    extra: jsonb("extra").$type<Record<string, string>>().notNull().default({}),
  },
  (t) => [index("patch_component_device_idx").on(t.deviceId, t.kind)],
);

/** CVE présente sur un équipement, rattachée à son composant et au correctif qui la ferme. */
export const patchVuln = pgTable(
  "patch_vuln",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    deviceId: integer("device_id")
      .notNull()
      .references(() => patchDevice.id, { onDelete: "cascade" }),
    cveId: text("cve_id").notNull(),
    /** os | app | package | bios */
    componentKind: text("component_kind").notNull(),
    componentName: text("component_name").notNull(),
    componentVersion: text("component_version").notNull().default(""),
    /** NVD | OSV */
    source: text("source").notNull(),
    advisory: text("advisory").notNull().default(""),
    cvss: real("cvss"),
    epss: real("epss"),
    kev: boolean("kev").notNull().default(false),
    ransomware: boolean("ransomware").notNull().default(false),
    score: integer("score").notNull().default(0),
    priority: text("priority").notNull().default("basse"),
    reasons: jsonb("reasons").$type<string[]>().notNull().default([]),
    fix: jsonb("fix").$type<Record<string, unknown>>().notNull().default({}),
    /** ouverte | corrigee | ignoree */
    status: text("status").notNull().default("ouverte"),
    ignoredReason: text("ignored_reason"),
    ignoredBy: text("ignored_by"),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
    fixedAt: timestamp("fixed_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("patch_vuln_dedup_idx").on(t.deviceId, t.cveId, t.componentName),
    index("patch_vuln_org_idx").on(t.orgId, t.status, t.score),
    index("patch_vuln_cve_idx").on(t.orgId, t.cveId),
  ],
);

/** Politique de correctifs : quoi, sur quels équipements, quand et avec quelle approbation. */
export const patchPolicy = pgTable(
  "patch_policy",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    name: text("name").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    /** { groups, tags, os, kinds } : listes vides = tous */
    target: jsonb("target").$type<Record<string, string[]>>().notNull().default({}),
    /** os | apps | all */
    content: text("content").notNull().default("all"),
    minPriority: text("min_priority").notNull().default("haute"),
    kevOnly: boolean("kev_only").notNull().default(false),
    /** auto | manuelle */
    approval: text("approval").notNull().default("manuelle"),
    /** { days: [1..7], start: "HH:MM", end: "HH:MM", tz } ; null = à tout moment */
    window: jsonb("window").$type<Record<string, unknown> | null>(),
    /** immediat | fenetre | utilisateur */
    reboot: text("reboot").notNull().default("fenetre"),
    rebootDeferHours: integer("reboot_defer_hours").notNull().default(24),
    maxParallel: integer("max_parallel").notNull().default(20),
    pilot: boolean("pilot").notNull().default(true),
    pilotThreshold: integer("pilot_threshold").notNull().default(100),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("patch_policy_org_idx").on(t.orgId)],
);

/** Déploiement de correctifs : un lot d'équipements, un anneau pilote puis la production. */
export const patchDeployment = pgTable(
  "patch_deployment",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    policyId: integer("policy_id").references(() => patchPolicy.id, { onDelete: "set null" }),
    title: text("title").notNull(),
    /** attente_approbation | planifie | pilote | production | termine | echec | annule */
    status: text("status").notNull(),
    /** { content, minPriority, kevOnly, cves } */
    selection: jsonb("selection").$type<Record<string, unknown>>().notNull().default({}),
    deviceIds: jsonb("device_ids").$type<number[]>().notNull().default([]),
    window: jsonb("window").$type<Record<string, unknown> | null>(),
    reboot: text("reboot").notNull().default("fenetre"),
    rebootDeferHours: integer("reboot_defer_hours").notNull().default(24),
    maxParallel: integer("max_parallel").notNull().default(20),
    pilot: boolean("pilot").notNull().default(true),
    pilotThreshold: integer("pilot_threshold").notNull().default(100),
    message: text("message").notNull().default(""),
    createdBy: text("created_by"),
    approvedBy: text("approved_by"),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    startedAt: timestamp("started_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("patch_deployment_org_idx").on(t.orgId, t.createdAt), index("patch_deployment_status_idx").on(t.status)],
);

/** Tâche envoyée à un agent : scan, installation, retour arrière, redémarrage. */
export const patchJob = pgTable(
  "patch_job",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    deviceId: integer("device_id")
      .notNull()
      .references(() => patchDevice.id, { onDelete: "cascade" }),
    deploymentId: integer("deployment_id").references(() => patchDeployment.id, { onDelete: "cascade" }),
    /** scan | install | rollback | reboot */
    action: text("action").notNull(),
    /** pilote | production (déploiements) */
    phase: text("phase"),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull().default({}),
    /** en_attente | envoye | succes | echec | annule */
    status: text("status").notNull().default("en_attente"),
    attempts: integer("attempts").notNull().default(0),
    result: jsonb("result").$type<Record<string, unknown> | null>(),
    log: text("log").notNull().default(""),
    notBefore: timestamp("not_before", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    sentAt: timestamp("sent_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("patch_job_device_idx").on(t.deviceId, t.status), index("patch_job_deployment_idx").on(t.deploymentId)],
);

/** Journal d'audit du module : chaque action d'un utilisateur ou d'un agent. */
export const patchAudit = pgTable(
  "patch_audit",
  {
    orgId: text("org_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    /** Adresse de l'utilisateur, « agent:<équipement> » ou « système » */
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    target: text("target").notNull().default(""),
    detail: jsonb("detail").$type<Record<string, unknown>>().notNull().default({}),
    at: timestamp("at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("patch_audit_org_idx").on(t.orgId, t.at)],
);

/** Cache des sources de vulnérabilités (NVD par produit, fiches OSV), partagé par tous. */
export const patchCache = pgTable("patch_cache", {
  key: text("key").primaryKey(),
  data: jsonb("data").$type<unknown>().notNull(),
  fetchedAt: timestamp("fetched_at", { withTimezone: true }).notNull().defaultNow(),
});

// ---------- Collecte dark web (Apify) et motifs surveillés ----------

/** Point de départ d'une collecte (adresse .onion), géré par les analystes de la plateforme : corpus commun. */
export const dwSource = pgTable("dw_source", {
  id: serial("id").primaryKey(),
  label: text("label").notNull(),
  url: text("url").notNull(),
  /** Mot-clé transmis à l'Actor (facultatif) */
  keyword: text("keyword").notNull().default(""),
  maxDepth: integer("max_depth").notNull().default(2),
  maxPages: integer("max_pages").notNull().default(200),
  active: boolean("active").notNull().default(true),
  createdBy: text("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastRunAt: timestamp("last_run_at", { withTimezone: true }),
});

/** Exécution d'un Actor Apify et avancement de son ingestion. */
export const dwRun = pgTable(
  "dw_run",
  {
    id: serial("id").primaryKey(),
    sourceId: integer("source_id").references(() => dwSource.id, { onDelete: "set null" }),
    apifyRunId: text("apify_run_id").notNull().unique(),
    datasetId: text("dataset_id").notNull().default(""),
    /** RUNNING | SUCCEEDED | FAILED | ABORTED | TIMED-OUT | READY-FOR-INGEST… puis INGESTED */
    status: text("status").notNull().default("RUNNING"),
    trigger: text("trigger").notNull().default("cron"),
    pages: integer("pages").notNull().default(0),
    ingested: integer("ingested").notNull().default(0),
    matches: integer("matches").notNull().default(0),
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    ingestedAt: timestamp("ingested_at", { withTimezone: true }),
  },
  (t) => [index("dw_run_status_idx").on(t.status)],
);

/** Motif recherché par une organisation dans le corpus (mot-clé, expression, regex, domaine, e-mail, portefeuille). */
export const dwPattern = pgTable(
  "dw_pattern",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    name: text("name").notNull(),
    /** keyword | phrase | regex | domain | email | wallet */
    kind: text("kind").notNull(),
    /** Valeur recherchée ; pour un e-mail, son empreinte seulement */
    value: text("value").notNull(),
    /** Valeur affichée (e-mail partiellement masqué) */
    display: text("display").notNull(),
    /** critique | haute | moyenne | info */
    severity: text("severity").notNull().default("haute"),
    active: boolean("active").notNull().default(true),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastMatchAt: timestamp("last_match_at", { withTimezone: true }),
    matchCount: integer("match_count").notNull().default(0),
  },
  (t) => [index("dw_pattern_org_idx").on(t.orgId)],
);

/** Page du corpus qui correspond à un motif d'une organisation (extrait déjà masqué). */
export const dwMatch = pgTable(
  "dw_match",
  {
    orgId: text("org_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    id: serial("id").primaryKey(),
    patternId: integer("pattern_id")
      .notNull()
      .references(() => dwPattern.id, { onDelete: "cascade" }),
    docId: text("doc_id").notNull(),
    url: text("url").notNull(),
    host: text("host").notNull().default(""),
    snippet: text("snippet").notNull().default(""),
    /** nouvelle | traitee | faux_positif */
    status: text("status").notNull().default("nouvelle"),
    collectedAt: timestamp("collected_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("dw_match_pattern_doc_idx").on(t.patternId, t.docId), index("dw_match_org_idx").on(t.orgId, t.createdAt)],
);

export const schema = { organization, orgMember, orgInvite, orgSettings, orgConnector, orgApiKey, user, session, account, verification, twoFactor, userSettings, cveStatus, exploit, ticket, watchItem, watchAccount, ctiAlert, leakSource, ingestJob, leakEvent, leakIndicator, leakMatch, huntAsset, huntObservation, huntFinding, huntSiem, huntRun, patchEnroll, patchDevice, patchComponent, patchVuln, patchPolicy, patchDeployment, patchJob, patchAudit, patchCache, dwSource, dwRun, dwPattern, dwMatch, cveAssignment, cveComment, passkey, feedback };
