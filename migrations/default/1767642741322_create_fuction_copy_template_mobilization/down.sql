ALTER TABLE public.blocks 
ALTER COLUMN created_at DROP DEFAULT,
ALTER COLUMN updated_at DROP DEFAULT;

ALTER TABLE public.widgets 
ALTER COLUMN created_at DROP DEFAULT,
ALTER COLUMN updated_at DROP DEFAULT;

DROP FUNCTION public.copy_template_mobilization(
    p_mobilization_id bigint,
    p_template_mobilization_id bigint
);