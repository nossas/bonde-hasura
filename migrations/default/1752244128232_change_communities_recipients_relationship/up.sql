ALTER TABLE recipients DROP COLUMN community_id CASCADE;

ALTER TABLE public.communities DROP CONSTRAINT fk_rails_a268b06370;

ALTER TABLE public.communities ADD CONSTRAINT fk_rails_a268b06370 FOREIGN KEY (recipient_id) REFERENCES public.recipients(id) ON DELETE SET NULL;