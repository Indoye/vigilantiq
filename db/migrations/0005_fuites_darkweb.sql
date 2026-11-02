CREATE TABLE "ingest_job" (
	"id" serial PRIMARY KEY NOT NULL,
	"source_id" integer NOT NULL,
	"idempotency_key" text NOT NULL,
	"payload" jsonb,
	"status" text DEFAULT 'queued' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"error" text,
	"result" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"processed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "leak_event" (
	"id" serial PRIMARY KEY NOT NULL,
	"source_id" integer NOT NULL,
	"external_id" text,
	"evidence_hash" text NOT NULL,
	"title" text NOT NULL,
	"actor" text DEFAULT '' NOT NULL,
	"victim" text DEFAULT '' NOT NULL,
	"victim_domain" text,
	"posted_at" timestamp with time zone,
	"observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"volume" integer,
	"data_classes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"price" text DEFAULT '' NOT NULL,
	"reference" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'claimed' NOT NULL,
	"reliability" text,
	"analyst_note" text DEFAULT '' NOT NULL,
	"qualified_by" text,
	"qualified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "leak_indicator" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" integer NOT NULL,
	"kind" text NOT NULL,
	"domain" text,
	"value_hash" text NOT NULL,
	"masked" text NOT NULL,
	"has_password" boolean DEFAULT false NOT NULL,
	"has_cookie" boolean DEFAULT false NOT NULL,
	"has_pii" boolean DEFAULT false NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "leak_match" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"watch_item_id" integer NOT NULL,
	"event_id" integer NOT NULL,
	"mode" text NOT NULL,
	"indicator_count" integer DEFAULT 0 NOT NULL,
	"score" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "leak_source" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"reliability" text DEFAULT 'F' NOT NULL,
	"language" text DEFAULT '' NOT NULL,
	"key_salt" text,
	"active" boolean DEFAULT true NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_ingest_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "ingest_job" ADD CONSTRAINT "ingest_job_source_id_leak_source_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."leak_source"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_event" ADD CONSTRAINT "leak_event_source_id_leak_source_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."leak_source"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_indicator" ADD CONSTRAINT "leak_indicator_event_id_leak_event_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."leak_event"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_match" ADD CONSTRAINT "leak_match_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_match" ADD CONSTRAINT "leak_match_watch_item_id_watch_item_id_fk" FOREIGN KEY ("watch_item_id") REFERENCES "public"."watch_item"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_match" ADD CONSTRAINT "leak_match_event_id_leak_event_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."leak_event"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "ingest_job_idem_idx" ON "ingest_job" USING btree ("source_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "ingest_job_status_idx" ON "ingest_job" USING btree ("status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "leak_event_evidence_idx" ON "leak_event" USING btree ("evidence_hash");--> statement-breakpoint
CREATE INDEX "leak_event_observed_idx" ON "leak_event" USING btree ("observed_at");--> statement-breakpoint
CREATE INDEX "leak_event_status_idx" ON "leak_event" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "leak_indicator_event_hash_idx" ON "leak_indicator" USING btree ("event_id","value_hash");--> statement-breakpoint
CREATE INDEX "leak_indicator_domain_idx" ON "leak_indicator" USING btree ("domain");--> statement-breakpoint
CREATE INDEX "leak_indicator_hash_idx" ON "leak_indicator" USING btree ("value_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "leak_match_dedup_idx" ON "leak_match" USING btree ("user_id","watch_item_id","event_id");--> statement-breakpoint
CREATE INDEX "leak_match_user_idx" ON "leak_match" USING btree ("user_id","updated_at");