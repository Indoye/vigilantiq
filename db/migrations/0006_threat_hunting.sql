CREATE TABLE "hunt_asset" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"name" text NOT NULL,
	"kind" text DEFAULT 'poste' NOT NULL,
	"source" text DEFAULT 'agent' NOT NULL,
	"hostname" text,
	"os" text DEFAULT '' NOT NULL,
	"last_ip" text,
	"key_salt" text,
	"last_seen_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_finding" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"asset_id" integer,
	"kind" text NOT NULL,
	"indicator_type" text NOT NULL,
	"indicator" text NOT NULL,
	"source" text NOT NULL,
	"threat" text DEFAULT '' NOT NULL,
	"malware" text DEFAULT '' NOT NULL,
	"severity" text DEFAULT 'moyenne' NOT NULL,
	"confidence" integer,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"status" text DEFAULT 'nouveau' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_observation" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"asset_id" integer NOT NULL,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"count" integer DEFAULT 1 NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hunt_run" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"kind" text NOT NULL,
	"trigger" text DEFAULT 'manuel' NOT NULL,
	"stats" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"report" text,
	"model" text,
	"error" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "hunt_siem" (
	"user_id" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"url" text NOT NULL,
	"index" text DEFAULT '' NOT NULL,
	"auth_enc" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_pull_at" timestamp with time zone,
	"last_error" text,
	"last_stats" jsonb,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "hunt_asset" ADD CONSTRAINT "hunt_asset_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_finding" ADD CONSTRAINT "hunt_finding_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_finding" ADD CONSTRAINT "hunt_finding_asset_id_hunt_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."hunt_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_observation" ADD CONSTRAINT "hunt_observation_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_observation" ADD CONSTRAINT "hunt_observation_asset_id_hunt_asset_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."hunt_asset"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_run" ADD CONSTRAINT "hunt_run_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_siem" ADD CONSTRAINT "hunt_siem_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "hunt_asset_user_name_idx" ON "hunt_asset" USING btree ("user_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "hunt_finding_dedup_idx" ON "hunt_finding" USING btree ("user_id","asset_id","kind","indicator");--> statement-breakpoint
CREATE INDEX "hunt_finding_user_idx" ON "hunt_finding" USING btree ("user_id","status","last_seen");--> statement-breakpoint
CREATE UNIQUE INDEX "hunt_obs_asset_kind_value_idx" ON "hunt_observation" USING btree ("asset_id","kind","value");--> statement-breakpoint
CREATE INDEX "hunt_obs_user_kind_value_idx" ON "hunt_observation" USING btree ("user_id","kind","value");--> statement-breakpoint
CREATE INDEX "hunt_obs_last_seen_idx" ON "hunt_observation" USING btree ("last_seen");--> statement-breakpoint
CREATE INDEX "hunt_run_user_idx" ON "hunt_run" USING btree ("user_id","started_at");