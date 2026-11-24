CREATE TABLE "sc_cache" (
	"key" text PRIMARY KEY NOT NULL,
	"status" integer NOT NULL,
	"etag" text,
	"body" jsonb,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sc_repo" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"repo" text NOT NULL,
	"added_by" text,
	"scan_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "sc_repo_org_repo" ON "sc_repo" USING btree ("org_id","repo");