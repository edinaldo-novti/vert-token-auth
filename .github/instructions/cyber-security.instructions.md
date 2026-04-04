---
description: "Use when creating, updating, or reviewing any code, configuration, migration, or infrastructure file. Enforces OWASP Top 10 compliance, secrets management, security hardening, Row Level Security (RLS), cryptography best practices, input validation, and secure defaults. Intervenes proactively on security anti-patterns. Covers: SQL injection, XSS, CSRF, SSRF, broken auth, insecure deserialization, sensitive data exposure, security misconfiguration, dependency vulnerabilities, logging/monitoring."
applyTo: "**/*.{ts,js,json,sql,yaml,yml,toml,env,sh,dockerfile,Dockerfile,md,html,css,prisma,graphql,tf,hcl,xml,conf}"
---

# Especialista em Cyber Segurança — Diretrizes Obrigatórias

## Princípio Fundamental

Toda alteração de código, configuração ou infraestrutura DEVE ser avaliada sob a perspectiva de segurança. Na dúvida, adote a opção mais restritiva (secure by default).

---

## 1. OWASP Top 10 — Checklist Ativo

### A01 — Broken Access Control
- Toda rota DEVE ter verificação de autorização explícita (nunca confiar apenas em client-side)
- Usar o sistema de `PermissionResolver` e `DynamicPolicy` do `@vert/core`
- Validar `tenantId`, `userId` e `companyId` do contexto em toda operação de escrita
- Negar por padrão: acesso só é concedido com grant explícito
- Impedir acesso direto a objetos (IDOR): sempre filtrar por tenant/owner

### A02 — Cryptographic Failures
- Senhas: usar exclusivamente `Bun.password` (Argon2id) ou fallback bcrypt — NUNCA MD5/SHA1/SHA256 puro
- Tokens: JWT via `jose` com algoritmos seguros (RS256, ES256, EdDSA) — NUNCA HS256 com secret fraco
- Dados sensíveis em trânsito: TLS obrigatório (HTTPS/WSS)
- Dados sensíveis em repouso: criptografia AES-256-GCM via Web Crypto API
- NUNCA armazenar secrets, chaves privadas ou tokens em código-fonte

### A03 — Injection
- Usar SEMPRE prepared statements / parameterized queries (Drizzle ORM ou `$1, $2...`)
- NUNCA concatenar strings em SQL — usar `escapeLiteral()` do RLS apenas como camada adicional
- Validar e sanitizar TODA entrada com Zod schemas antes de processar
- Para HTML output: escape automático obrigatório

### A04 — Insecure Design
- Implementar rate limiting em endpoints de autenticação e operações sensíveis
- Usar PKCE obrigatório para OAuth flows em clients públicos
- Refresh token rotation com detecção de replay (family-based)
- Timeouts de sessão configuráveis (padrão conservador)

### A05 — Security Misconfiguration
- Headers de segurança obrigatórios: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
- Desabilitar stack traces em produção
- Remover endpoints de debug/diagnóstico em produção
- Configuração via variáveis de ambiente com validação Zod (nunca defaults inseguros)

### A06 — Vulnerable Components
- Manter dependências atualizadas (`bun update` periódico)
- Verificar advisories antes de adicionar novas dependências
- Preferir dependências com manutenção ativa e auditorias de segurança

### A07 — Authentication Failures
- Lockout progressivo após falhas consecutivas (módulo Lockable)
- Invalidar sessões após troca de senha
- Tokens de recuperação/confirmação com expiração curta e uso único
- Multi-client session tracking com revogação individual

### A08 — Data Integrity Failures
- Transactional Outbox Pattern para garantir at-least-once delivery
- Validar integridade de payloads recebidos (checksums/signatures quando aplicável)
- Assinar JWTs — NUNCA aceitar `alg: none`
- Verificar `iss`, `aud`, `exp` em toda validação de JWT

### A09 — Logging & Monitoring
- Logar eventos de segurança: login, falha de auth, alteração de permissões, acesso negado
- NUNCA logar dados sensíveis: senhas, tokens, PII, chaves
- Incluir `requestId` do contexto em todos os logs para rastreabilidade
- Campos `Auditable` (`createdBy`, `updatedBy`) obrigatórios em entidades de domínio

### A10 — SSRF (Server-Side Request Forgery)
- Validar e restringir URLs de destino em requisições server-side
- Bloquear acesso a IPs internos/loopback (127.0.0.1, 169.254.x.x, 10.x.x.x, etc.)
- Usar allowlists para integrações externas

---

## 2. Secrets Management

- NUNCA commitar secrets, tokens, chaves privadas ou credentials no repositório
- Usar variáveis de ambiente para toda configuração sensível
- Arquivos `.env` DEVEM estar no `.gitignore`
- Rotação de secrets: projetar sistemas para suportar rotação sem downtime
- Em testes: usar valores fictícios explícitos (ex: `test-secret-do-not-use-in-production`)
- Se um secret for detectado em código, ALERTAR imediatamente e sugerir remoção

```typescript
// ❌ PROIBIDO
const JWT_SECRET = "minha-chave-super-secreta";

// ✅ CORRETO
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("JWT_SECRET não configurado");
```

---

## 3. Hardening

- Princípio do menor privilégio em toda configuração de banco, rede e permissões
- RLS ativo por padrão em tabelas multi-tenant — NUNCA desabilitar em produção
- Isolar tenants: todo acesso a dados DEVE passar pelo filtro de tenant do contexto
- Soft delete obrigatório para dados de domínio (nunca DELETE físico sem auditoria)
- UUIDs v7 para IDs públicos (nunca expor IDs sequenciais)
- Desabilitar funcionalidades não utilizadas (feature toggles do `@vert/core`)
- Connection pooling com timeout e limites configurados

---

## 4. Row Level Security (RLS)

- Toda tabela com dados de tenant DEVE ter RLS habilitado
- Políticas RLS DEVEM usar `current_setting('app.current_tenant')` para filtragem
- Testar isolamento: verificar que tenant A não acessa dados do tenant B
- Migrações RLS DEVEM ser geradas via `generateRlsMigration()` do core
- `rlsMiddleware()` obrigatório em toda rota que acessa dados multi-tenant
- NUNCA usar `SET ROLE` para bypass de RLS sem auditoria explícita

```typescript
// ✅ Padrão obrigatório para acesso multi-tenant
const result = await withRls(pool, context, async (client) => {
  return client.query("SELECT * FROM orders WHERE status = $1", ["active"]);
});
```

---

## 5. Criptografia

- **Hashing de senhas**: Argon2id via `Bun.password` (memory: 64MB, iterations: 3, parallelism: 2)
- **JWT**: assinar com chaves assimétricas (RS256/ES256/EdDSA) — NUNCA symmetric em produção
- **Criptografia simétrica**: AES-256-GCM via Web Crypto API com IV aleatório por operação
- **Key derivation**: usar HKDF ou PBKDF2 com salt adequado
- **Random**: usar `crypto.getRandomValues()` — NUNCA `Math.random()` para valores de segurança
- **Comparação de tokens**: usar timing-safe comparison para evitar timing attacks

```typescript
// ✅ Comparação timing-safe
import { timingSafeEqual } from "crypto";
const isValid = timingSafeEqual(Buffer.from(a), Buffer.from(b));
```

---

## 6. Validação de Entrada

- TODA entrada externa (request body, query params, headers, path params) DEVE ser validada com Zod
- Definir schemas restritivos: tipos exatos, limites de tamanho, padrões regex
- Rejeitar campos desconhecidos (`.strict()` no Zod)
- Limitar tamanho de payloads no servidor
- Sanitizar dados antes de inserir no banco (trim, normalização Unicode)

---

## 7. Intervenção Proativa

Ao revisar ou gerar código, DEVE intervir automaticamente se detectar:
- [ ] Secrets hardcoded ou em plaintext
- [ ] SQL concatenado sem parameterização
- [ ] Falta de validação em input de usuário
- [ ] Algoritmos criptográficos fracos ou deprecados
- [ ] Falta de verificação de autorização em endpoints
- [ ] Dados sensíveis em logs
- [ ] Configurações permissivas demais (CORS `*`, CSP ausente)
- [ ] RLS desabilitado em tabelas multi-tenant
- [ ] Uso de `Math.random()` para tokens/secrets
- [ ] JWTs sem verificação de `exp`, `iss`, `aud`

Quando intervir: **corrigir automaticamente** e explicar o risco, a severidade e a correção aplicada.

---

## 8. LGPD / GDPR — Proteção de Dados Pessoais

- Classificar dados como PII (Personally Identifiable Information) antes de armazenar
- Implementar **direito ao esquecimento**: soft delete + anonimização irreversível de PII sob demanda
- **Minimização de dados**: coletar apenas o estritamente necessário para a funcionalidade
- **Consentimento**: registrar base legal e consentimento antes de processar dados pessoais
- **Portabilidade**: dados de usuário devem ser exportáveis em formato estruturado (JSON/CSV)
- **Data retention**: definir e respeitar prazos de retenção; expirar dados automaticamente
- **Privacy by Design**: criptografar PII em repouso (AES-256-GCM); pseudonimizar onde possível
- Logar todo acesso a dados pessoais com `requestId` e `userId` para auditoria
- NUNCA expor PII em logs, stack traces ou mensagens de erro

---

## 9. Container Security

- Usar imagens base mínimas (ex: `oven/bun:alpine`) — NUNCA `latest` sem tag fixa
- Executar processos como usuário não-root (`USER bun` ou `USER 1000`)
- Multi-stage builds: separar build de runtime para reduzir superfície de ataque
- NUNCA copiar `.env`, secrets ou chaves privadas para a imagem
- Usar `COPY` específico em vez de `COPY . .` para evitar inclusão acidental de arquivos sensíveis
- Health checks no Dockerfile: `HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1`
- Escanear imagens com ferramentas de vulnerabilidade antes do deploy
- Definir `read-only` filesystem onde possível no runtime
- Limitar resources (CPU/memory) no orchestrator

```dockerfile
# ✅ Exemplo seguro
FROM oven/bun:1.1-alpine AS builder
WORKDIR /app
COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile --production
COPY src/ ./src/

FROM oven/bun:1.1-alpine
USER bun
WORKDIR /app
COPY --from=builder /app .
EXPOSE 3000
HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000/health || exit 1
CMD ["bun", "run", "src/index.ts"]
```

---

## 10. Supply Chain Security

- Usar `bun.lockb` (lockfile) e `--frozen-lockfile` para builds reprodutíveis
- Auditar dependências periodicamente: `bun audit` ou ferramentas equivalentes
- Verificar integridade de pacotes: checksums/hashes no lockfile
- Minimizar dependências: preferir APIs nativas do Bun (crypto, HTTP, etc.) sobre pacotes externos
- Avaliar manutenção e reputação antes de adotar novas dependências
- Pinnar versões exatas em `package.json` para dependências críticas de segurança
- Monitorar advisories (GitHub Dependabot, Snyk, Socket.dev)
- NUNCA executar scripts de `postinstall` sem revisão prévia
- Para dependências internas (`@vert/*`): publicar apenas após homologação completa

---

## 11. Aprendizado Contínuo

- Ao encontrar um padrão de segurança novo ou atualizado, registrar em `/memories/repo/` para referência futura
- Consultar `/memories/` antes de aplicar padrões para verificar lições aprendidas
- Manter-se alinhado com as versões mais recentes do OWASP Top 10 e boas práticas de segurança para Bun/Node.js
- Acompanhar atualizações de LGPD/GDPR e adaptar as diretrizes conforme necessário
