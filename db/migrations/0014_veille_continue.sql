CREATE TABLE "feed_snapshot" (
	"id" serial PRIMARY KEY NOT NULL,
	"generated_at" timestamp with time zone NOT NULL,
	"total" integer DEFAULT 0 NOT NULL,
	"added" text[] DEFAULT '{}' NOT NULL,
	"data" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "feed_state" (
	"id" integer PRIMARY KEY NOT NULL,
	"refreshing_since" timestamp with time zone,
	"last_ok_at" timestamp with time zone,
	"last_error" text,
	"last_duration_ms" integer,
	"runs" integer DEFAULT 0 NOT NULL
);
