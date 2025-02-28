CREATE FUNCTION get_widget_donation_stats(widget_id integer)
RETURNS SETOF widget_donation_stats AS $$
    select
        w.id as widget_id,
        json_build_object(
        'pledged', sum(d.amount / 100) + coalesce(nullif(w.settings::json->>'external_resource', ''), '0')::bigint,
        'widget_id', w.id,
        'goal', w.goal,
        'progress', ((sum(d.amount / 100) + coalesce(nullif(w.settings::json->>'external_resource', ''), '0')::bigint) / w.goal) * 100,
        'total_donations', (count(distinct d.id)),
        'total_donators', (count(distinct d.activist_id))
        ) as stats
    from widgets w
        join donations d on d.widget_id = w.id
        where w.id = $1 and
            d.transaction_status = 'paid'
        group by w.id;
$$ LANGUAGE sql STABLE;
