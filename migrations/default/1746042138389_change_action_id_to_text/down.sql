
ALTER TABLE "analyze".activist_actions DROP CONSTRAINT activist_actions_pkey;

ALTER TABLE "analyze".activist_actions
  ALTER COLUMN action_id TYPE bigint USING action_id::bigint;

ALTER TABLE "analyze".activist_actions
  ADD CONSTRAINT activist_actions_pkey PRIMARY KEY (action, action_id);
