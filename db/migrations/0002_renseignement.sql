CREATE TABLE "cti_alert" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"source" text NOT NULL,
	"external_id" text NOT NULL,
	"watch_value" text DEFAULT '' NOT NULL,
	"severity" text DEFAULT 'moyenne' NOT NULL,
	"title" text NOT NULL,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"url" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"seen_at" timestamp with time zone,
	"notified_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "watch_item" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"kind" text NOT NULL,
	"value" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_scan_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "cti_alert" ADD CONSTRAINT "cti_alert_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "watch_item" ADD CONSTRAINT "watch_item_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "cti_alert_dedup_idx" ON "cti_alert" USING btree ("user_id","source","external_id");--> statement-breakpoint
CREATE INDEX "cti_alert_user_created_idx" ON "cti_alert" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "watch_item_user_value_idx" ON "watch_item" USING btree ("user_id","kind","value");