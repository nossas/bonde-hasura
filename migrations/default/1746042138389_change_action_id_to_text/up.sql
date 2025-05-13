
DROP MATERIALIZED VIEW "analyze".donations_not_sync;

ALTER TABLE "analyze".activist_actions DROP CONSTRAINT activist_actions_pkey;

ALTER TABLE "analyze".activist_actions
  ALTER COLUMN action_id TYPE text USING action_id::text;

ALTER TABLE "analyze".activist_actions
  ADD CONSTRAINT activist_actions_pkey PRIMARY KEY (action, action_id);
