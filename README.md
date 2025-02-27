# Gerenciamento do Hasura Engine - BONDE

## Sobre o Hasura Engine
O [Hasura Engine](https://hasura.io/) é uma plataforma que fornece uma API GraphQL em tempo real para bancos de dados PostgreSQL. Ele permite a criação de consultas e mutações dinâmicas sem a necessidade de escrever um backend manualmente.

## O que são Migrações e Metadatas?
O Hasura gerencia as configurações do banco de dados através de:
- **Migrações**: Versão controlada das alterações no esquema do banco de dados.
- **Metadatas**: Configurações do Hasura, incluindo permissões, regras de acesso, eventos e relacionamentos dinâmicos.

## Requisitos
Antes de iniciar, certifique-se de ter:
- [Hasura CLI](https://hasura.io/docs/latest/graphql/core/hasura-cli/install-hasura-cli.html) instalado.
- Um endpoint GraphQL configurado.
- O segredo de administrador do Hasura.

## Configuração do Ambiente
As configurações são gerenciadas via arquivo `.env`. Crie um arquivo `.env` na raiz do projeto e adicione as variáveis:

```
HASURA_GRAPHQL_ADMIN_SECRET=seu_token_aqui
HASURA_GRAPHQL_ENDPOINT=http://api-graphql.bonde.devel
```

## Comandos Principais

### Abrir o Console do Hasura
```sh
hasura console
```

### Exportar Metadatas
```sh
hasura metadata export
```

### Exibir Migrações Aplicadas
```sh
hasura migrate diff
```

### Aplicar Migrações
```sh
hasura migrate apply
```

## Contribuição
Para modificar as configurações do Hasura, utilize os comandos acima para manipular as migrações e metadatas. Sempre valide suas alterações antes de aplicá-las em produção.

## Contato
Dúvidas ou sugestões? Entre em contato com a equipe de desenvolvimento da plataforma BONDE.