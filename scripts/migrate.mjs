// Applique les migrations de la base avant la compilation (appelé par « npm run build »).
// Sans DATABASE_URL, on passe : le projet compile quand même, les comptes seront indisponibles.
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

const url = process.env.DATABASE_URL;
if (!url) {
  console.log("Migrations : DATABASE_URL absente, étape ignorée.");
  process.exit(0);
}
const client = postgres(url, { prepare: false, max: 1 });
try {
  await migrate(drizzle(client), { migrationsFolder: new URL("../db/migrations", import.meta.url).pathname });
  console.log("Migrations : base à jour.");
} catch (e) {
  console.error("Migrations : échec.", e);
  process.exitCode = 1;
} finally {
  await client.end();
}
