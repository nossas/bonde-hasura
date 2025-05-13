
CREATE TABLE "analyze".activist_action_sync_log (
  action text NOT NULL,
  action_id text NOT NULL,
  integration_name text NOT NULL,
  synced_at timestamp NOT NULL DEFAULT now(),
  success boolean NOT NULL DEFAULT true,
  response_metadata jsonb NULL,
  PRIMARY KEY (action, action_id, integration_name),
  CONSTRAINT fk_activist_action
    FOREIGN KEY (action, action_id)
    REFERENCES "analyze".activist_actions (action, action_id)
    ON DELETE CASCADE
);
