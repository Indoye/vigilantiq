CREATE TABLE "patch_audit" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"target" text DEFAULT '' NOT NULL,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patch_cache" (
	"key" text PRIMARY KEY NOT NULL,
	"data" jsonb NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patch_component" (
	"id" serial PRIMARY KEY NOT NULL,
	"device_id" integer NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"vendor" text DEFAULT '' NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	"source" text DEFAULT '' NOT NULL,
	"extra" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patch_deployment" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"policy_id" integer,
	"title" text NOT NULL,
	"status" text NOT NULL,
	"selection" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"device_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"window" jsonb,
	"reboot" text DEFAULT 'fenetre' NOT NULL,
	"reboot_defer_hours" integer DEFAULT 24 NOT NULL,
	"max_parallel" integer DEFAULT 20 NOT NULL,
	"pilot" boolean DEFAULT true NOT NULL,
	"pilot_threshold" integer DEFAULT 100 NOT NULL,
	"message" text DEFAULT '' NOT NULL,
	"created_by" text,
	"approved_by" text,
	"approved_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "patch_device" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"machine_id" text NOT NULL,
	"name" text NOT NULL,
	"hostname" text DEFAULT '' NOT NULL,
	"kind" text DEFAULT 'poste' NOT NULL,
	"os_family" text NOT NULL,
	"os_name" text DEFAULT '' NOT NULL,
	"os_version" text DEFAULT '' NOT NULL,
	"arch" text DEFAULT '' NOT NULL,
	"ip" text,
	"domain" text DEFAULT '' NOT NULL,
	"logged_user" text DEFAULT '' NOT NULL,
	"group_name" text DEFAULT '' NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ring" text DEFAULT 'production' NOT NULL,
	"hardware" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"key_salt" text,
	"agent_version" text DEFAULT '' NOT NULL,
	"app_manager" boolean DEFAULT false NOT NULL,
	"reboot_pending" boolean DEFAULT false NOT NULL,
	"inventory_requested" boolean DEFAULT true NOT NULL,
	"last_seen_at" timestamp with time zone,
	"last_inventory_at" timestamp with time zone,
	"correlated_at" timestamp with time zone,
	"correlate_error" text,
	"enrolled_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patch_enroll" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"key_salt" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "patch_enroll_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "patch_job" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"device_id" integer NOT NULL,
	"deployment_id" integer,
	"action" text NOT NULL,
	"phase" text,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text DEFAULT 'en_attente' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"result" jsonb,
	"log" text DEFAULT '' NOT NULL,
	"not_before" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sent_at" timestamp with time zone,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "patch_policy" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"name" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"target" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"content" text DEFAULT 'all' NOT NULL,
	"min_priority" text DEFAULT 'haute' NOT NULL,
	"kev_only" boolean DEFAULT false NOT NULL,
	"approval" text DEFAULT 'manuelle' NOT NULL,
	"window" jsonb,
	"reboot" text DEFAULT 'fenetre' NOT NULL,
	"reboot_defer_hours" integer DEFAULT 24 NOT NULL,
	"max_parallel" integer DEFAULT 20 NOT NULL,
	"pilot" boolean DEFAULT true NOT NULL,
	"pilot_threshold" integer DEFAULT 100 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patch_vuln" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"device_id" integer NOT NULL,
	"cve_id" text NOT NULL,
	"component_kind" text NOT NULL,
	"component_name" text NOT NULL,
	"component_version" text DEFAULT '' NOT NULL,
	"source" text NOT NULL,
	"advisory" text DEFAULT '' NOT NULL,
	"cvss" real,
	"epss" real,
	"kev" boolean DEFAULT false NOT NULL,
	"ransomware" boolean DEFAULT false NOT NULL,
	"score" integer DEFAULT 0 NOT NULL,
	"priority" text DEFAULT 'basse' NOT NULL,
	"reasons" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"fix" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text DEFAULT 'ouverte' NOT NULL,
	"ignored_reason" text,
	"ignored_by" text,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"fixed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "patch_audit" ADD CONSTRAINT "patch_audit_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_component" ADD CONSTRAINT "patch_component_device_id_patch_device_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."patch_device"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_deployment" ADD CONSTRAINT "patch_deployment_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_deployment" ADD CONSTRAINT "patch_deployment_policy_id_patch_policy_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."patch_policy"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_device" ADD CONSTRAINT "patch_device_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_enroll" ADD CONSTRAINT "patch_enroll_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_job" ADD CONSTRAINT "patch_job_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_job" ADD CONSTRAINT "patch_job_device_id_patch_device_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."patch_device"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_job" ADD CONSTRAINT "patch_job_deployment_id_patch_deployment_id_fk" FOREIGN KEY ("deployment_id") REFERENCES "public"."patch_deployment"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_policy" ADD CONSTRAINT "patch_policy_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_vuln" ADD CONSTRAINT "patch_vuln_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_vuln" ADD CONSTRAINT "patch_vuln_device_id_patch_device_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."patch_device"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "patch_audit_user_idx" ON "patch_audit" USING btree ("user_id","at");--> statement-breakpoint
CREATE INDEX "patch_component_device_idx" ON "patch_component" USING btree ("device_id","kind");--> statement-breakpoint
CREATE INDEX "patch_deployment_user_idx" ON "patch_deployment" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "patch_deployment_status_idx" ON "patch_deployment" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "patch_device_machine_idx" ON "patch_device" USING btree ("user_id","machine_id");--> statement-breakpoint
CREATE INDEX "patch_device_user_idx" ON "patch_device" USING btree ("user_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "patch_job_device_idx" ON "patch_job" USING btree ("device_id","status");--> statement-breakpoint
CREATE INDEX "patch_job_deployment_idx" ON "patch_job" USING btree ("deployment_id");--> statement-breakpoint
CREATE INDEX "patch_policy_user_idx" ON "patch_policy" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "patch_vuln_dedup_idx" ON "patch_vuln" USING btree ("device_id","cve_id","component_name");--> statement-breakpoint
CREATE INDEX "patch_vuln_user_idx" ON "patch_vuln" USING btree ("user_id","status","score");--> statement-breakpoint
CREATE INDEX "patch_vuln_cve_idx" ON "patch_vuln" USING btree ("user_id","cve_id");