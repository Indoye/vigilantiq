CREATE TABLE "exploit" (
	"url" text PRIMARY KEY NOT NULL,
	"cve_id" text NOT NULL,
	"source" text NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"stars" integer DEFAULT 0 NOT NULL,
	"published_at" timestamp with time zone,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ticket" (
	"cve_id" text NOT NULL,
	"connector" text NOT NULL,
	"external_id" text DEFAULT '' NOT NULL,
	"url" text DEFAULT '' NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ticket" ADD CONSTRAINT "ticket_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "exploit_cve_idx" ON "exploit" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "exploit_first_seen_idx" ON "exploit" USING btree ("first_seen");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_cve_connector_idx" ON "ticket" USING btree ("cve_id","connector");