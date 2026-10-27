import { boolean, index, integer, pgTable, primaryKey, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

// ---------- Tables de Better Auth (comptes, sessions, connexions Google, jetons) ----------

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

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

export const schema = { user, session, account, verification, userSettings, cveStatus, exploit, ticket };
