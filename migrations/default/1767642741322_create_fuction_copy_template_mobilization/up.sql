CREATE OR REPLACE FUNCTION public.copy_template_mobilization(
    p_mobilization_id bigint,
    p_template_mobilization_id bigint
)
RETURNS SETOF public.mobilizations
LANGUAGE plpgsql
VOLATILE
AS $BODY$
DECLARE
    v_template RECORD;
    v_template_block RECORD;
    v_new_block_id bigint;
BEGIN
    -- 1. Buscar o template
    SELECT * INTO v_template
    FROM public.template_mobilizations
    WHERE id = p_template_mobilization_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Template % not found', p_template_mobilization_id;
    END IF;
    
    -- 2. Verificar se mobilization existe
    IF NOT EXISTS (SELECT 1 FROM public.mobilizations WHERE id = p_mobilization_id) THEN
        RAISE EXCEPTION 'Mobilization % not found', p_mobilization_id;
    END IF;
    
    -- 3. Verificar se mobilization já tem blocks
    IF EXISTS (SELECT 1 FROM public.blocks WHERE mobilization_id = p_mobilization_id) THEN
        RAISE EXCEPTION 'Mobilization % already has blocks', p_mobilization_id;
    END IF;
    
    -- 4. Copiar campos do template para mobilization
    UPDATE public.mobilizations SET
        color_scheme = v_template.color_scheme,
        header_font = v_template.header_font,
        body_font = v_template.body_font,
        facebook_share_title = v_template.facebook_share_title,
        facebook_share_description = v_template.facebook_share_description,
        facebook_share_image = v_template.facebook_share_image,
        twitter_share_text = v_template.twitter_share_text,
        goal = v_template.goal,
        favicon = v_template.favicon,
        updated_at = NOW()
    WHERE id = p_mobilization_id;
    
    -- 5. Copiar blocks
    FOR v_template_block IN
        SELECT * FROM public.template_blocks
        WHERE template_mobilization_id = p_template_mobilization_id
        ORDER BY position
    LOOP
        INSERT INTO public.blocks (
            mobilization_id,
            bg_class,
            bg_image,
            position,
            hidden,
            name,
            menu_hidden
        ) VALUES (
            p_mobilization_id,
            v_template_block.bg_class,
            v_template_block.bg_image,
            v_template_block.position,
            COALESCE(v_template_block.hidden, false),
            v_template_block.name,
            COALESCE(v_template_block.menu_hidden, false)
        ) RETURNING id INTO v_new_block_id;
        
        -- Copiar widgets (convertendo hstore para jsonb)
        INSERT INTO public.widgets (
            block_id,
            settings,
            kind,
            sm_size,
            md_size,
            lg_size
        )
        SELECT
            v_new_block_id,
            hstore_to_jsonb(tw.settings),  -- Converter hstore para jsonb
            tw.kind,
            tw.sm_size,
            tw.md_size,
            tw.lg_size
        FROM public.template_widgets tw
        WHERE tw.template_block_id = v_template_block.id;
    END LOOP;
    
    -- 6. Incrementar contador do template
    UPDATE public.template_mobilizations
    SET uses_number = COALESCE(uses_number, 0) + 1,
        updated_at = NOW()
    WHERE id = p_template_mobilization_id;
    
    -- 7. Retornar mobilization atualizada
    RETURN QUERY
    SELECT * FROM public.mobilizations
    WHERE id = p_mobilization_id;
END;
$BODY$;