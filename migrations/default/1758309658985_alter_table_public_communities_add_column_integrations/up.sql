alter table "public"."communities" add column "integrations" jsonb
 null default jsonb_build_object();
