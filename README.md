# NEXUS ONE — RC1 1.0.1

MVP técnico do NEXUS ONE com persistência PostgreSQL, autenticação, multi-tenant, queue/worker, IA configurável, memória/contexto e camada de ferramentas.

## Implementado
- PostgreSQL como persistência principal
- Cadastro/login/logout com sessão HTTP-only
- Users, Organizations e Memberships
- Projetos e missões por organização
- Isolamento de tenant no backend
- Fila persistida em PostgreSQL + worker embutido
- IA DEMO/LIVE configurável
- Validação estruturada no modo LIVE
- Memória de projeto e recuperação de contexto
- Tool Executor
- Ferramenta calculator local
- Adaptador `web_search` configurável via `WEB_SEARCH_URL`
- Registro auditável de tool calls
- Endpoint de consulta de tool calls por missão

## Rodar localmente

Requisitos: Node.js 20+, Docker e PostgreSQL.

```bash
docker compose -f infrastructure/docker-compose.yml up -d
npm install
```

Aplicar migrations em ordem:

```bash
psql "$DATABASE_URL" -f db/migrations/0001_initial.sql
psql "$DATABASE_URL" -f db/migrations/0002_auth_sessions.sql
psql "$DATABASE_URL" -f db/migrations/0003_jobs.sql
psql "$DATABASE_URL" -f db/migrations/0004_ai_usage.sql
psql "$DATABASE_URL" -f db/migrations/0005_core_validation.sql
psql "$DATABASE_URL" -f db/migrations/0006_memory_context.sql
psql "$DATABASE_URL" -f db/migrations/0007_tools.sql
```

Copie `.env.example` para `.env` e configure as variáveis.

```bash
npm start
```

Abra `http://localhost:3000`.

## Endpoints principais
- `GET /api/health`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/:id/memories`
- `GET /api/missions`
- `POST /api/missions`
- `GET /api/missions/:id`
- `GET /api/missions/:id/tools`
- `GET /api/jobs/:id`

## Ferramentas
`calculator` é local e não exige fornecedor externo.

`web_search` exige uma API de busca compatível configurada por `WEB_SEARCH_URL` e, quando necessário, `WEB_SEARCH_API_KEY`. O NEXUS não finge pesquisa quando essa integração não existe: a ferramenta falha explicitamente.

## Importante
Esta é uma versão de desenvolvimento/MVP. Ainda não é produção. Antes de venda pública ainda faltam, entre outros: hardening de segurança, MFA do proprietário, billing real, payouts, observabilidade de produção, deploy, QA end-to-end e documentação jurídica.


## V0.9 — Billing + Credits

Billing V0.9 adds plans, subscriptions, payments, checkout sessions and a credit ledger.

For local testing, use `BILLING_MODE=DEMO`. The demo checkout endpoint simulates a successful payment; it is not a production payment integration.

### Database
Apply migrations through `db/migrations/0001_initial.sql` through `0008_billing.sql`.

### Flow
`GET /api/billing/plans` → list plans.

`GET /api/billing/me` → current subscription and credit balance.

`POST /api/billing/checkout` body `{ "plan": "PRO" }` → creates demo checkout.

`POST /api/billing/checkout/:id/complete` → completes the demo payment when `BILLING_MODE=DEMO`.

`GET /api/billing/credits` → credit balance and ledger.

In production, replace the demo provider with a real payment processor and verify provider webhooks before changing subscription or credit state.

## V1.0 Owner Console
Configure `OWNER_EMAIL` to the email of the platform owner, apply migration `0009_owner_audit.sql`, then open `/admin.html` after login. The owner endpoints are server-protected and do not rely on frontend-only hiding.


## RC1 — Production Hardening

Esta versão acrescenta uma camada inicial de hardening para o ambiente de produção:
- security headers HTTP
- limite de payload
- rate limiting básico por endereço de origem
- validação de Origin para requisições mutáveis quando `PUBLIC_ORIGIN` está definido
- `Secure` deve ser usado em cookie de produção através da configuração final de deployment
- encerramento gracioso de servidor e pool PostgreSQL
- validações de configuração quando `NODE_ENV=production`

### Antes de produção pública
O RC1 ainda exige configuração real do provedor de IA, gateway de pagamento, secrets, domínio HTTPS, MFA do proprietário, monitoramento externo, backup/restore testado e QA end-to-end. O rate limiting desta versão é local ao processo e deve ser substituído ou complementado por um mecanismo distribuído quando houver múltiplas instâncias.

## V1.0.2 — Pre-flight e Go-Live

A versão 1.0.2 adiciona um comando de pré-voo para evitar deploy com configuração incompleta.

```bash
npm install
npm run check
npm run preflight
```

Em produção, o pre-flight exige, entre outros, `AI_MODE=LIVE`, `BILLING_MODE=LIVE`, HTTPS, credenciais reais de IA, `PAYMENT_PROVIDER`, `PAYMENT_WEBHOOK_SECRET` e um `OWNER_EMAIL` real.

> O pre-flight valida configuração; ele não substitui testes end-to-end, revisão de segurança, configuração do gateway, backup/restore ou homologação jurídica.

## V1.0.3 — Deploy reproduzível
- `npm run migrate` aplica migrations pendentes em ordem e registra as já aplicadas.
- `Dockerfile` usa Node 24 Alpine para runtime de produção.
- `infrastructure/docker-compose.production.yml` sobe PostgreSQL, executa migrations e inicia a aplicação.

### Deploy local com Docker
1. Copie `.env.example` para `.env` e configure valores reais.
2. Defina `POSTGRES_PASSWORD` e uma `DATABASE_URL` compatível com o serviço `db` (por exemplo `postgres://nexus:SENHA@db:5432/nexus` dentro da rede Docker).
3. Execute `docker compose -f infrastructure/docker-compose.production.yml up --build`.

Este compose é uma base de implantação, não substitui TLS/reverse proxy, secrets manager, backups externos, observabilidade e configuração do provedor de pagamento/IA.
