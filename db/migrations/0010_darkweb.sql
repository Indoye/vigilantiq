CREATE TABLE "dw_match" (
	"org_id" text NOT NULL,
	"id" serial PRIMARY KEY NOT NULL,
	"pattern_id" integer NOT NULL,
	"doc_id" text NOT NULL,
	"url" text NOT NULL,
	"host" text DEFAULT '' NOT NULL,
	"snippet" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'nouvelle' NOT NULL,
	"collected_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dw_pattern" (
	"org_id" text NOT NULL,
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"display" text NOT NULL,
	"severity" text DEFAULT 'haute' NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_match_at" timestamp with time zone,
	"match_count" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dw_run" (
	"id" serial PRIMARY KEY NOT NULL,
	"source_id" integer,
	"apify_run_id" text NOT NULL,
	"dataset_id" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'RUNNING' NOT NULL,
	"trigger" text DEFAULT 'cron' NOT NULL,
	"pages" integer DEFAULT 0 NOT NULL,
	"ingested" integer DEFAULT 0 NOT NULL,
	"matches" integer DEFAULT 0 NOT NULL,
	"error" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"ingested_at" timestamp with time zone,
	CONSTRAINT "dw_run_apify_run_id_unique" UNIQUE("apify_run_id")
);
--> statement-breakpoint
CREATE TABLE "dw_source" (
	"id" serial PRIMARY KEY NOT NULL,
	"label" text NOT NULL,
	"url" text NOT NULL,
	"keyword" text DEFAULT '' NOT NULL,
	"max_depth" integer DEFAULT 2 NOT NULL,
	"max_pages" integer DEFAULT 200 NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_run_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "dw_match" ADD CONSTRAINT "dw_match_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dw_match" ADD CONSTRAINT "dw_match_pattern_id_dw_pattern_id_fk" FOREIGN KEY ("pattern_id") REFERENCES "public"."dw_pattern"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dw_pattern" ADD CONSTRAINT "dw_pattern_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dw_run" ADD CONSTRAINT "dw_run_source_id_dw_source_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."dw_source"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "dw_match_pattern_doc_idx" ON "dw_match" USING btree ("pattern_id","doc_id");--> statement-breakpoint
CREATE INDEX "dw_match_org_idx" ON "dw_match" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "dw_pattern_org_idx" ON "dw_pattern" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "dw_run_status_idx" ON "dw_run" USING btree ("status");