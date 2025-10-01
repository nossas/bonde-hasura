alter table "public"."blocks" alter column "hidden" drop not null;
ALTER TABLE "public"."blocks" ALTER COLUMN "hidden" drop default;
