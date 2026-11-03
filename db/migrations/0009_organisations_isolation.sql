ALTER TABLE "patch_enroll" DROP CONSTRAINT "patch_enroll_user_id_unique";--> statement-breakpoint
ALTER TABLE "cti_alert" DROP CONSTRAINT "cti_alert_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "cve_status" DROP CONSTRAINT "cve_status_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "hunt_asset" DROP CONSTRAINT "hunt_asset_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "hunt_finding" DROP CONSTRAINT "hunt_finding_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "hunt_observation" DROP CONSTRAINT "hunt_observation_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "hunt_run" DROP CONSTRAINT "hunt_run_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "hunt_siem" DROP CONSTRAINT "hunt_siem_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "leak_match" DROP CONSTRAINT "leak_match_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_audit" DROP CONSTRAINT "patch_audit_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_deployment" DROP CONSTRAINT "patch_deployment_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_device" DROP CONSTRAINT "patch_device_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_enroll" DROP CONSTRAINT "patch_enroll_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_job" DROP CONSTRAINT "patch_job_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_policy" DROP CONSTRAINT "patch_policy_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "patch_vuln" DROP CONSTRAINT "patch_vuln_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "watch_account" DROP CONSTRAINT "watch_account_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "watch_item" DROP CONSTRAINT "watch_item_user_id_user_id_fk";
--> statement-breakpoint
DROP INDEX "cti_alert_user_created_idx";--> statement-breakpoint
DROP INDEX "hunt_asset_user_name_idx";--> statement-breakpoint
DROP INDEX "hunt_finding_user_idx";--> statement-breakpoint
DROP INDEX "hunt_obs_user_kind_value_idx";--> statement-breakpoint
DROP INDEX "hunt_run_user_idx";--> statement-breakpoint
DROP INDEX "leak_match_user_idx";--> statement-breakpoint
DROP INDEX "patch_audit_user_idx";--> statement-breakpoint
DROP INDEX "patch_deployment_user_idx";--> statement-breakpoint
DROP INDEX "patch_device_user_idx";--> statement-breakpoint
DROP INDEX "patch_policy_user_idx";--> statement-breakpoint
DROP INDEX "patch_vuln_user_idx";--> statement-breakpoint
DROP INDEX "ticket_cve_connector_idx";--> statement-breakpoint
DROP INDEX "watch_account_user_email_idx";--> statement-breakpoint
DROP INDEX "watch_item_user_value_idx";--> statement-breakpoint
DROP INDEX "cti_alert_dedup_idx";--> statement-breakpoint
DROP INDEX "hunt_finding_dedup_idx";--> statement-breakpoint
DROP INDEX "leak_match_dedup_idx";--> statement-breakpoint
DROP INDEX "patch_device_machine_idx";--> statement-breakpoint
DROP INDEX "patch_vuln_cve_idx";--> statement-breakpoint
ALTER TABLE "cve_status" DROP CONSTRAINT "cve_status_user_id_cve_id_pk";--> statement-breakpoint
ALTER TABLE "cti_alert" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "cve_status" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "hunt_asset" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "hunt_finding" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "hunt_observation" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "hunt_run" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "hunt_siem" DROP CONSTRAINT IF EXISTS "hunt_siem_pkey";--> statement-breakpoint
ALTER TABLE "hunt_siem" ADD PRIMARY KEY ("org_id");--> statement-breakpoint
ALTER TABLE "hunt_siem" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "leak_match" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_audit" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_deployment" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_device" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_enroll" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_job" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_policy" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "patch_vuln" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "ticket" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "watch_account" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "watch_item" ALTER COLUMN "org_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "cve_status" ADD CONSTRAINT "cve_status_org_id_cve_id_pk" PRIMARY KEY("org_id","cve_id");--> statement-breakpoint
CREATE INDEX "cti_alert_org_created_idx" ON "cti_alert" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "hunt_asset_org_name_idx" ON "hunt_asset" USING btree ("org_id","name");--> statement-breakpoint
CREATE INDEX "hunt_finding_org_idx" ON "hunt_finding" USING btree ("org_id","status","last_seen");--> statement-breakpoint
CREATE INDEX "hunt_obs_org_kind_value_idx" ON "hunt_observation" USING btree ("org_id","kind","value");--> statement-breakpoint
CREATE INDEX "hunt_run_org_idx" ON "hunt_run" USING btree ("org_id","started_at");--> statement-breakpoint
CREATE INDEX "leak_match_org_idx" ON "leak_match" USING btree ("org_id","updated_at");--> statement-breakpoint
CREATE INDEX "patch_audit_org_idx" ON "patch_audit" USING btree ("org_id","at");--> statement-breakpoint
CREATE INDEX "patch_deployment_org_idx" ON "patch_deployment" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "patch_device_org_idx" ON "patch_device" USING btree ("org_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "patch_policy_org_idx" ON "patch_policy" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "patch_vuln_org_idx" ON "patch_vuln" USING btree ("org_id","status","score");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_org_cve_connector_idx" ON "ticket" USING btree ("org_id","cve_id","connector");--> statement-breakpoint
CREATE UNIQUE INDEX "watch_account_org_email_idx" ON "watch_account" USING btree ("org_id","email");--> statement-breakpoint
CREATE UNIQUE INDEX "watch_item_org_value_idx" ON "watch_item" USING btree ("org_id","kind","value");--> statement-breakpoint
CREATE UNIQUE INDEX "cti_alert_dedup_idx" ON "cti_alert" USING btree ("org_id","source","external_id");--> statement-breakpoint
CREATE UNIQUE INDEX "hunt_finding_dedup_idx" ON "hunt_finding" USING btree ("org_id","asset_id","kind","indicator");--> statement-breakpoint
CREATE UNIQUE INDEX "leak_match_dedup_idx" ON "leak_match" USING btree ("org_id","watch_item_id","event_id");--> statement-breakpoint
CREATE UNIQUE INDEX "patch_device_machine_idx" ON "patch_device" USING btree ("org_id","machine_id");--> statement-breakpoint
CREATE INDEX "patch_vuln_cve_idx" ON "patch_vuln" USING btree ("org_id","cve_id");--> statement-breakpoint
ALTER TABLE "cti_alert" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "cve_status" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "hunt_asset" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "hunt_finding" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "hunt_observation" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "hunt_run" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "hunt_siem" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "leak_match" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_audit" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_deployment" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_device" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_enroll" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_job" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_policy" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_vuln" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "user_settings" DROP COLUMN "stack";--> statement-breakpoint
ALTER TABLE "watch_account" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "watch_item" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "patch_enroll" ADD CONSTRAINT "patch_enroll_org_id_unique" UNIQUE("org_id");