---
description: "Use when creating, updating, or reviewing ANY code file. Enforces Bun-native architecture over Rails/MVC patterns. Auto-corrects Node.js polyfills, MVC terminology, and anti-patterns that ignore Bun's built-in APIs. This project is a port of Ruby gems — Rails idioms MUST be translated to Bun-native equivalents, never copied verbatim."
applyTo: "**/*.{ts,js,json,toml}"
---

# Arquitetura Bun-Nativa — Diretrizes Obrigatórias

## Princípio Fundamental

Este projeto é um port de gems Ruby/Rails para Bun/TypeScript. **Toda adaptação DEVE usar APIs nativas do Bun** ao invés de polyfills Node.js ou padrões MVC do Rails. Ao encontrar código que viola essas regras, corrija-o imediatamente.

---

## 1. Arquitetura: Handlers, NÃO Controllers

### ❌ PROIBIDO — Padrões MVC/Rails

- Diretórios `controllers/`, `models/`, `views/`
- Classes com sufixo `Controller` (`UsersController`, `SessionsController`)
- Arquivo chamado `controller-methods.ts` ou similar
- Herança de `ApplicationController` ou `BaseController`
- Callbacks Rails (`before_action`, `after_action`, `around_action`)
- `params` hash (usar `req.json()`, `req.formData()`, `new URL(req.url).searchParams`)

### ✅ OBRIGATÓRIO — Padrões Bun-Nativos

```
src/
  handlers/        # Funções que recebem Request e retornam Response
  services/        # Lógica de negócio pura (sem HTTP)
  db/              # Schemas, migrations, queries (adaptadores de banco)
  middleware/      # Funções composáveis (req) → resultado
  policies/        # Autorização (DynamicPolicy, PermissionResolver)
  config/          # Configuração com Zod schemas
  jobs/            # Background tasks
  tests/           # Testes com bun:test
```

- **Handler** = `(req: Request | BunRequest) => Response | Promise<Response>`
- **Middleware** = função composável que recebe `Request` e retorna resultado tipado
- **Service** = lógica pura sem dependência HTTP (testável isoladamente)

---

## 2. APIs Nativas do Bun — Usar SEMPRE

### Servidor HTTP

```typescript
// ✅ CORRETO — Bun.serve() com route map nativo
Bun.serve({
  port: Number(process.env.PORT) || 3000,
  routes: {
    "/api/status": (req) => Response.json({ ok: true }),
    "/api/users/:id": (req) => handleUser(req),
  },
  fetch(req) {
    return new Response("Not Found", { status: 404 });
  },
});

// ❌ PROIBIDO — Express/Fastify/Hono patterns dentro do Bun
// app.get("/api/status", (req, res) => res.json({ ok: true }));
```

### Password Hashing

```typescript
// ✅ CORRETO — Bun.password (Argon2id nativo, sem dependência externa)
const hash = await Bun.password.hash(password, {
  algorithm: "argon2id",
  memoryCost: 65536, // 64 MB
  timeCost: 3,
});
const valid = await Bun.password.verify(password, hash);

// ❌ PROIBIDO — bcrypt, scrypt, ou qualquer lib externa para hashing de senha
```

### Arquivo I/O

```typescript
// ✅ CORRETO — Bun.file() + Bun.write()
const content = await Bun.file("config.json").text();
await Bun.write("output.txt", data);

// ❌ EVITAR — node:fs/promises (usar apenas se Bun.file/write não cobrir o caso)
// import { readFile, writeFile } from "node:fs/promises";
```

### Hashing Criptográfico

```typescript
// ✅ CORRETO — Bun.CryptoHasher para hashing rápido
const hasher = new Bun.CryptoHasher("sha256");
hasher.update(data);
const hash = hasher.digest("hex");

// ✅ TAMBÉM CORRETO — Web Crypto API (para operações async)
const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));

// ❌ EVITAR — node:crypto createHash (usar Bun.CryptoHasher)
// import { createHash } from "node:crypto";
```

### Build & Bundler

```typescript
// ✅ CORRETO — bun build com target bun
// package.json: "build": "bun build ./src/index.ts --outdir ./dist --target bun"

// ❌ PROIBIDO — esbuild, webpack, rollup, ou outros bundlers
```

### Testes

```typescript
// ✅ CORRETO — bun:test nativo
import { describe, test, expect, beforeEach } from "bun:test";

// ❌ PROIBIDO — jest, vitest, mocha, ou outro test runner
```

### Bytes & Encoding

```typescript
// ✅ CORRETO — TextEncoder/TextDecoder (Web API padrão, Bun-otimizado)
const bytes = new TextEncoder().encode(text);
const text = new TextDecoder().decode(bytes);

// ✅ CORRETO para comparação timing-safe
const a = new TextEncoder().encode(value1);
const b = new TextEncoder().encode(value2);
if (a.length !== b.length) return false;
return crypto.subtle.timingSafeEqual(a, b); // Web Crypto API

// ❌ EVITAR — Buffer.from() (preferir typed arrays)
```

---

## 3. Tradução Rails → Bun — Referência

| Conceito Rails | Equivalente Bun/Vert |
|---|---|
| `ApplicationController` | Handler function `(req: Request) => Response` |
| `before_action` | Middleware composável chamado no handler |
| `params` | `req.json()`, `req.formData()`, `URL.searchParams` |
| `render json:` | `Response.json(data, { status })` |
| `render status: 404` | `new Response("Not Found", { status: 404 })` |
| `ActiveRecord::Base` | Adapter pattern (`UserAdapter` interface) |
| `ActiveRecord::Migration` | SQL migrations em `migrations/` |
| `ApplicationRecord.find(id)` | `adapter.findById(id)` |
| `has_secure_password` (bcrypt) | `Bun.password.hash()` (Argon2id) |
| `ActiveSupport::Concern` | Module export com funções composáveis |
| `config/routes.rb` | `src/config/routes.ts` com route map tipado |
| `Devise` modules | `@vert/auth` modules (Authenticatable, etc.) |
| `Pundit` policies | `@vert/core` DynamicPolicy + PermissionResolver |
| `Doorkeeper` OAuth | `@vert/oauth` (a implementar) |
| `Rails.cache` | `CacheAdapter` interface (Redis/in-memory) |
| `ActiveJob` | `src/jobs/` com funções async |
| `ActionMailer` | `MailerAdapter` interface |
| `rescue_from` | `try/catch` no handler ou middleware de error |
| `scope` (ActiveRecord) | Query builder functions em `src/db/` |

---

## 4. Response Patterns — Bun Nativo

```typescript
// JSON response
Response.json({ data }, { status: 200 });

// Error response
Response.json({ error: "Not found" }, { status: 404 });

// Redirect
Response.redirect("/login", 302);

// Empty response
new Response(null, { status: 204 });

// Headers de segurança (aplicar em todo Response de API)
new Response(body, {
  headers: {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  },
});
```

---

## 5. Auto-Correção — Regras de Intervenção

Ao encontrar qualquer um destes padrões, **CORRIJA IMEDIATAMENTE**:

1. **Diretório `controllers/`** → Renomear para `handlers/`
2. **Diretório `models/`** → Renomear para `db/`
3. **`import { readFile } from "node:fs/promises"`** → Usar `Bun.file().text()`
4. **`import { writeFile } from "node:fs/promises"`** → Usar `Bun.write()`
5. **`import { createHash } from "node:crypto"`** → Usar `Bun.CryptoHasher`
6. **`Buffer.from()`** → Usar `new TextEncoder().encode()`
7. **`Buffer.toString()`** → Usar `new TextDecoder().decode()`
8. **Classe com sufixo `Controller`** → Converter para handler function
9. **`before_action`/callback chains** → Middleware composável
10. **`params.require().permit()`** → Zod schema + `req.json()`
11. **`require("express")`/`require("fastify")`** → `Bun.serve()`
12. **`jest`/`vitest` imports** → `bun:test`
13. **`bcrypt`/`argon2` (npm)** → `Bun.password`
14. **Comentários referenciando "Controller" na arquitetura** → Atualizar para "Handler"

---

## 6. Convenções de Nomenclatura

| Tipo | Padrão | Exemplo |
|---|---|---|
| Handler | `verbNoun` ou `handleNoun` | `createUser`, `handleLogin` |
| Middleware | `nounMiddleware` | `authMiddleware`, `rlsMiddleware` |
| Service | `verbNoun` | `authenticateUser`, `generateToken` |
| Policy | `NounPolicy` | `UserPolicy`, `OrderPolicy` |
| Adapter | `NounAdapter` | `UserAdapter`, `CacheAdapter` |
| Config | `defineNounConfig` | `defineAuthConfig`, `defineConfig` |
| Schema (Zod) | `nounSchema` | `loginSchema`, `authConfigSchema` |
| Test file | `noun.test.ts` | `auth.test.ts`, `jwt.test.ts` |
| Type | `PascalCase` | `AuthUser`, `JwtKeyPair` |

---

## 7. Checklist de Revisão

Antes de finalizar qualquer alteração, verifique:

- [ ] Nenhum `import` de `node:fs/promises` onde `Bun.file`/`Bun.write` resolve
- [ ] Nenhum `import` de `node:crypto` onde `Bun.CryptoHasher` ou Web Crypto resolve
- [ ] Nenhum uso de `Buffer` onde `TextEncoder`/`TextDecoder`/`Uint8Array` resolve
- [ ] Nenhum diretório ou arquivo com nomenclatura MVC (`controller`, `model`, `view`)
- [ ] `Bun.password` para todo hashing de senha (nunca bcrypt/scrypt externo)
- [ ] `bun:test` para todos os testes (nunca jest/vitest)
- [ ] `Bun.serve()` para servidor HTTP (nunca express/fastify/hono)
- [ ] `Response` / `Response.json()` para respostas (nunca `res.send()`/`res.json()`)
- [ ] `Request` nativo como input dos handlers (nunca objetos custom de framework)
- [ ] Build com `bun build --target bun` (nunca esbuild/webpack)
