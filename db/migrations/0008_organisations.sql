CREATE TABLE "org_api_key" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"prefix" text NOT NULL,
	"key_hash" text NOT NULL,
	"scope" text DEFAULT 'lecture' NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "org_connector" (
	"org_id" text NOT NULL,
	"type" text NOT NULL,
	"config_enc" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"auto_send" boolean DEFAULT false NOT NULL,
	"last_error" text,
	"last_run_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "org_connector_org_id_type_pk" PRIMARY KEY("org_id","type")
);
--> statement-breakpoint
CREATE TABLE "org_invite" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"email" text NOT NULL,
	"role" text DEFAULT 'analyst' NOT NULL,
	"token_hash" text NOT NULL,
	"invited_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "org_member" (
	"org_id" text NOT NULL,
	"user_id" text NOT NULL,
	"role" text DEFAULT 'viewer' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "org_settings" (
	"org_id" text PRIMARY KEY NOT NULL,
	"stack" text DEFAULT '' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "cti_alert" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "cve_status" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "hunt_asset" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "hunt_finding" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "hunt_observation" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "hunt_run" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "hunt_siem" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "leak_event" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "leak_match" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "leak_source" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_audit" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_deployment" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_device" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_enroll" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_job" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_policy" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "patch_vuln" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "ticket" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "watch_account" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "watch_item" ADD COLUMN "org_id" text;--> statement-breakpoint
ALTER TABLE "org_api_key" ADD CONSTRAINT "org_api_key_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_api_key" ADD CONSTRAINT "org_api_key_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_connector" ADD CONSTRAINT "org_connector_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_invite" ADD CONSTRAINT "org_invite_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_invite" ADD CONSTRAINT "org_invite_invited_by_user_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_member" ADD CONSTRAINT "org_member_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_member" ADD CONSTRAINT "org_member_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_settings" ADD CONSTRAINT "org_settings_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "org_api_key_hash_idx" ON "org_api_key" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "org_api_key_org_idx" ON "org_api_key" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "org_invite_token_idx" ON "org_invite" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "org_invite_email_idx" ON "org_invite" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "org_member_user_idx" ON "org_member" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "org_member_org_idx" ON "org_member" USING btree ("org_id");--> statement-breakpoint
ALTER TABLE "cti_alert" ADD CONSTRAINT "cti_alert_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_status" ADD CONSTRAINT "cve_status_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_asset" ADD CONSTRAINT "hunt_asset_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_finding" ADD CONSTRAINT "hunt_finding_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_observation" ADD CONSTRAINT "hunt_observation_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_run" ADD CONSTRAINT "hunt_run_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hunt_siem" ADD CONSTRAINT "hunt_siem_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_event" ADD CONSTRAINT "leak_event_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_match" ADD CONSTRAINT "leak_match_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "leak_source" ADD CONSTRAINT "leak_source_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_audit" ADD CONSTRAINT "patch_audit_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_deployment" ADD CONSTRAINT "patch_deployment_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_device" ADD CONSTRAINT "patch_device_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_enroll" ADD CONSTRAINT "patch_enroll_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_job" ADD CONSTRAINT "patch_job_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_policy" ADD CONSTRAINT "patch_policy_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patch_vuln" ADD CONSTRAINT "patch_vuln_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket" ADD CONSTRAINT "ticket_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "watch_account" ADD CONSTRAINT "watch_account_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "watch_item" ADD CONSTRAINT "watch_item_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
INSERT INTO "organization" ("id", "name", "created_at") SELECT 'org_' || "id", COALESCE(NULLIF(split_part("email", '@', 2), ''), "name"), "created_at" FROM "user" ON CONFLICT DO NOTHING;--> statement-breakpoint
INSERT INTO "org_member" ("org_id", "user_id", "role", "created_at") SELECT 'org_' || "id", "id", 'owner', "created_at" FROM "user" ON CONFLICT DO NOTHING;--> statement-breakpoint
INSERT INTO "org_settings" ("org_id", "stack") SELECT 'org_' || "user_id", "stack" FROM "user_settings" ON CONFLICT DO NOTHING;--> statement-breakpoint
UPDATE "cve_status" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "watch_item" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "watch_account" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "cti_alert" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "leak_match" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "hunt_asset" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "hunt_observation" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "hunt_finding" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "hunt_siem" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "hunt_run" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_enroll" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_device" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_vuln" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_policy" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_deployment" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_job" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "patch_audit" SET "org_id" = 'org_' || "user_id" WHERE "org_id" IS NULL;--> statement-breakpoint
UPDATE "ticket" SET "org_id" = COALESCE('org_' || "created_by", (SELECT 'org_' || "id" FROM "user" ORDER BY "created_at" LIMIT 1)) WHERE "org_id" IS NULL;--> statement-breakpoint
DELETE FROM "ticket" WHERE "org_id" IS NULL;
