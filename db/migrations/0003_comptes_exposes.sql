CREATE TABLE "watch_account" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"domain" text NOT NULL,
	"email" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"breaches" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"stealers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"checked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "watch_item" ADD COLUMN "verify_token" text;--> statement-breakpoint
ALTER TABLE "watch_item" ADD COLUMN "verified_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "watch_account" ADD CONSTRAINT "watch_account_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "watch_account_user_email_idx" ON "watch_account" USING btree ("user_id","email");--> statement-breakpoint
CREATE INDEX "watch_account_checked_idx" ON "watch_account" USING btree ("checked_at");