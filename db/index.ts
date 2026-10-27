import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { schema } from "./schema";

type Db = PostgresJsDatabase<typeof schema>;

const g = globalThis as unknown as { __vigilantiqDb?: Db };

/**
 * Connexion paresseuse : rien ne se connecte tant qu'aucune requête n'est faite,
 * ce qui permet de compiler le projet sans DATABASE_URL.
 */
export function getDb(): Db {
  if (!g.__vigilantiqDb) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL n’est pas configurée");
    // prepare: false pour rester compatible avec les pools de connexions (Neon, Supabase, PgBouncer).
    const client = postgres(url, { prepare: false, max: Number(process.env.DATABASE_POOL_MAX || 5) });
    g.__vigilantiqDb = drizzle(client, { schema });
  }
  return g.__vigilantiqDb;
}

export function dbConfigured(): boolean {
  return Boolean(process.env.DATABASE_URL);
}
