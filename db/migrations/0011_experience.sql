CREATE TABLE "cve_assignment" (
	"org_id" text NOT NULL,
	"cve_id" text NOT NULL,
	"assignee_id" text NOT NULL,
	"assigned_by" text,
	"assigned_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cve_assignment_org_id_cve_id_pk" PRIMARY KEY("org_id","cve_id")
);
--> statement-breakpoint
CREATE TABLE "cve_comment" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"cve_id" text NOT NULL,
	"user_id" text,
	"body" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "user_settings" ADD COLUMN "onboarding_hidden" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "user_settings" ADD COLUMN "notifications_seen_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "cve_assignment" ADD CONSTRAINT "cve_assignment_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_assignment" ADD CONSTRAINT "cve_assignment_assignee_id_user_id_fk" FOREIGN KEY ("assignee_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_comment" ADD CONSTRAINT "cve_comment_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_comment" ADD CONSTRAINT "cve_comment_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "cve_assignment_user_idx" ON "cve_assignment" USING btree ("assignee_id");--> statement-breakpoint
CREATE INDEX "cve_comment_org_cve_idx" ON "cve_comment" USING btree ("org_id","cve_id","created_at");