CREATE TABLE "public"."widget_actions" (
    "id" serial NOT NULL,
    "widget_id" integer NOT NULL,
    "mobilization_id" integer NOT NULL,
    "community_id" integer NOT NULL,
    "activist_id" integer NOT NULL,
    "first_name" varchar(80) NOT NULL,
    "last_name" varchar(150) NOT NULL,
    "email" text NOT NULL,
    "phone_number" text,
    "custom_fields" jsonb NOT NULL DEFAULT jsonb_build_object(),
    "created_at" timestamptz NOT NULL DEFAULT now(),
    "kind" text NOT NULL,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("activist_id") REFERENCES "public"."activists"("id") ON UPDATE restrict ON DELETE restrict,
    FOREIGN KEY ("community_id") REFERENCES "public"."communities"("id") ON UPDATE restrict ON DELETE restrict,
    FOREIGN KEY ("mobilization_id") REFERENCES "public"."mobilizations"("id") ON UPDATE restrict ON DELETE restrict,
    FOREIGN KEY ("widget_id") REFERENCES "public"."widgets"("id") ON UPDATE restrict ON DELETE restrict,
    UNIQUE ("id")
);

COMMENT ON TABLE "public"."widget_actions" IS E'Armazenar novos Tipos de Ações de Ativistas';
