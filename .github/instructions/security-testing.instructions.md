---
description: "Use when writing, reviewing, or updating tests related to security: authentication, authorization, RLS isolation, input validation, injection prevention, token handling, crypto operations, rate limiting, OWASP compliance testing. Covers unit tests, integration tests, and security regression tests."
applyTo: "**/*.test.{ts,js}"
---

# Diretrizes de Testes de Segurança

## Princípio

Todo mecanismo de segurança DEVE ter testes automatizados que validem tanto o comportamento correto quanto a resistência a ataques. Testes de segurança são tão críticos quanto os testes funcionais.

---

## 1. Isolamento de Tenant (RLS)

- Testar que tenant A **não** consegue ler dados do tenant B
- Testar que tenant A **não** consegue atualizar/deletar dados do tenant B
- Testar comportamento quando `tenantId` está ausente (deve falhar)
- Testar concurrent requests com tenants diferentes (usar `Promise.all`)
- Validar que `withRls()` faz rollback em caso de erro

```typescript
import { describe, test, expect } from "bun:test";

describe("RLS Isolation", () => {
  test("tenant A cannot access tenant B data", async () => {
    const ctxA = { tenantId: "tenant-a", userId: "user-1" };
    const ctxB = { tenantId: "tenant-b", userId: "user-2" };

    await withRls(pool, ctxA, async (client) => {
      await client.query("INSERT INTO orders (name) VALUES ($1)", ["Order A"]);
    });

    const result = await withRls(pool, ctxB, async (client) => {
      return client.query("SELECT * FROM orders");
    });

    expect(result.rows).toHaveLength(0);
  });

  test("concurrent tenant requests are isolated", async () => {
    const [resultA, resultB] = await Promise.all([
      withRls(pool, ctxA, (c) => c.query("SELECT current_setting('app.current_tenant')")),
      withRls(pool, ctxB, (c) => c.query("SELECT current_setting('app.current_tenant')")),
    ]);

    expect(resultA.rows[0].current_setting).toBe("tenant-a");
    expect(resultB.rows[0].current_setting).toBe("tenant-b");
  });
});
```

---

## 2. Autenticação

- Testar login com credenciais válidas → sucesso
- Testar login com senha incorreta → falha genérica (não revelar se user existe)
- Testar lockout após N tentativas falhadas
- Testar desbloqueio após tempo configurado
- Testar que tokens de recuperação expiram e são de uso único
- Testar invalidação de sessões após troca de senha

```typescript
test("account locks after max failed attempts", async () => {
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    await login(email, "wrong-password");
  }
  const result = await login(email, correctPassword);
  expect(result.error).toContain("locked");
});
```

---

## 3. Autorização

- Testar que usuário sem permissão recebe 403
- Testar que super-admin bypassa verificações normais
- Testar herança de roles (role pai → filho)
- Testar deny explícito sobrepõe grant
- Testar field-level access (campos bloqueados retornam `undefined`)
- Testar que `DynamicPolicy` mapeia CRUD corretamente

```typescript
test("denied permission overrides grant", async () => {
  const resolver = new PermissionResolver(adapter);
  // user tem grant via role, mas deny explícito
  const result = await resolver.resolve("user-1", "orders.delete");
  expect(result.allowed).toBe(false);
});
```

---

## 4. Injection Prevention

- Testar SQL injection via input de usuário → deve ser bloqueado
- Testar XSS via campos de texto → deve ser sanitizado
- Testar path traversal em uploads/downloads → deve rejeitar `../`
- Testar command injection se houver exec → deve sanitizar

```typescript
test("SQL injection attempt is safely parameterized", async () => {
  const malicious = "'; DROP TABLE users; --";
  const result = await searchUsers(malicious);
  // Não deve causar erro de SQL, apenas retornar vazio
  expect(result).toEqual([]);
  // Tabela users ainda existe
  const check = await pool.query("SELECT 1 FROM users LIMIT 1");
  expect(check.rows).toBeDefined();
});
```

---

## 5. Tokens & JWT

- Testar que JWT expirado é rejeitado
- Testar que JWT com `alg: none` é rejeitado
- Testar que JWT com issuer/audience incorreto é rejeitado
- Testar refresh token rotation: token antigo é invalidado
- Testar replay detection: uso de token da mesma família após rotação → revogar toda família
- Testar PKCE: code_verifier incorreto falha

```typescript
test("rejects JWT with alg:none", async () => {
  const fakeToken = `${btoa('{"alg":"none"}')}.${btoa('{"sub":"hacker"}')}.`;
  const result = await verifyToken(fakeToken);
  expect(result.valid).toBe(false);
});
```

---

## 6. Validação de Input

- Testar que payloads sem campos obrigatórios retornam 400
- Testar que campos extras (mass assignment) são rejeitados (`.strict()`)
- Testar limites de tamanho (strings longas, arrays grandes)
- Testar tipos incorretos (string onde espera number)
- Testar valores edge case: string vazia, null, undefined, NaN, Infinity

---

## 7. Rate Limiting

- Testar que N+1 requests dentro da janela retornam 429
- Testar que requests são liberadas após reset da janela
- Testar que rate limit é por IP/user (não global)

---

## 8. Dados Sensíveis

- Testar que respostas da API NÃO contêm: `password`, `passwordHash`, `secret`, `token` (exceto onde intencional)
- Testar que logs NÃO contêm PII ou credentials
- Testar que erros em produção NÃO expõem stack traces

---

## 9. Convenções de Teste

- Prefixar describes de segurança com `[Security]` para fácil identificação
- Usar `test.todo()` para cenários de segurança pendentes (nunca ignorar)
- Testes de segurança DEVEM rodar em CI — nunca marcar como `.skip`
- Isolar testes com dados próprios (não compartilhar estado entre testes de segurança)
- Nomes de teste descritivos: descrever ataque e resultado esperado

```typescript
describe("[Security] Authentication - Brute Force Protection", () => {
  test("locks account after 5 consecutive failed login attempts", async () => { /* ... */ });
  test("returns generic error message on failed login", async () => { /* ... */ });
  test("tracks failed attempt count in database", async () => { /* ... */ });
});
```
