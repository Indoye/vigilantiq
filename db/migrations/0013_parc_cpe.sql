CREATE TABLE "patch_cpe_map" (
	"id" serial PRIMARY KEY NOT NULL,
	"scope" text DEFAULT '*' NOT NULL,
	"key" text NOT NULL,
	"label" text DEFAULT '' NOT NULL,
	"vendor" text DEFAULT '' NOT NULL,
	"product" text DEFAULT '' NOT NULL,
	"title" text DEFAULT '' NOT NULL,
	"status" text NOT NULL,
	"confidence" integer DEFAULT 0 NOT NULL,
	"checked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "patch_cpe_map_scope_key_idx" ON "patch_cpe_map" USING btree ("scope","key");