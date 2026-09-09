# Spring Security Inspector

Current release: **0.2.0**

> **Static analysis for Spring Security configurations — directly in VS Code.**

Inspect your Spring Security setup, reconcile controller endpoints with security rules, detect authorization vulnerabilities, and simulate access rights — all without leaving the editor.

---

## ✨ Features

### 📊 Interactive Security Dashboard

Open the full-page dashboard with **`Spring Security: Open Security Dashboard`**:

- **KPI Cards** — Total security matchers, controller endpoints detected, findings by severity, Spring Security version.
- **Access Control Matrix** — Cross-references every `@RestController` endpoint with its matched Spring Security rule. Filterable and searchable.
- **Request Authorization Simulator** — Pick a method (`GET`, `POST`…), a path (`/api/admin/users`) and a role (`ROLE_USER`), and get an instant **ALLOWED / DENIED** verdict with the matched rule and reason. Custom expressions are marked **manual review required** instead of being assumed safe. Runs entirely against your actual security configuration.
- **One-click Exports** — Generate a full audit report in **Markdown** or export raw data as **JSON**.
- **CI Export** — Export findings as **SARIF** for GitHub Code Scanning and other CI security tools.
- **Findings Tab** — All detected issues ranked by severity with CWE links and file locations.

---

### 🌲 Security Overview (Activity Bar)

A structured tree view of your entire Spring Security setup:

| Section | What it shows |
|:---|:---|
| **Security Rules** | HTTP method, URL pattern, access level (`🔓 Public`, `🔑 Auth Required`, `🛡 Role Required`, `⛔ Deny All`), required roles |
| **Controller Endpoints** | All `@RestController` / `@Controller` methods with their resolved full path |
| **Security Findings** | Sorted by severity — errors first, then warnings, then info. Rich Markdown tooltips with CWE links |
| **Authentication** | `PasswordEncoder` beans (BCrypt, Argon2, NoOp), `UserDetailsService`, `AuthenticationProvider` |
| **Filter Chain** | Custom filters, **Session Policy** (STATELESS / ALWAYS / etc.), **CORS config**, **X-Frame-Options** |
| **Method Security** | `@PreAuthorize`, `@Secured`, `@RolesAllowed` annotations |

Click any item to jump directly to the exact file and line in the editor.

---

### 🔍 Vulnerability Detection Engine (OWASP / CWE)

| Rule ID | CWE | Severity | Description |
|:---|:---|:---|:---|
| `SPRING_SEC_UNPROTECTED_ENDPOINT` | CWE-284 | ⚠️ Warning | Controller endpoint matched by no explicit security rule |
| `SPRING_SEC_ENDPOINT_EXPOSED_VIA_CATCHALL` | CWE-284 | ⛔ Error | Endpoint public via generic `/**` permitAll catch-all |
| `SPRING_SEC_DEAD_MATCHER` | — | ℹ️ Info | Security matcher protecting a URL with no corresponding controller |
| `SPRING_SEC_ROUTE_SHADOWED` | CWE-698 | ⚠️ Warning | Broad rule (`/**`) placed before a more specific restrictive rule |
| `SPRING_SEC_CSRF_DISABLED` | CWE-352 | ⚠️ Warning | CSRF protection disabled — no `SessionCreationPolicy.STATELESS` detected |
| `SPRING_SEC_CSRF_DISABLED_STATELESS` | CWE-352 | ℹ️ Info | CSRF disabled but `STATELESS` session policy detected — acceptable for JWT APIs |
| `SPRING_SEC_CATCH_ALL_PERMIT` | CWE-284 | ⛔ Error | `.anyRequest().permitAll()` exposes everything publicly |
| `SPRING_SEC_NOOPENCODER` | CWE-256 | ⛔ Error | `NoOpPasswordEncoder` stores passwords as plain text |
| `SPRING_SEC_CORS_WILDCARD_CREDENTIALS` | CWE-942 | ⛔ Error | `allowedOrigins("*")` combined with `allowCredentials(true)` — browser will block |
| `SPRING_SEC_FRAME_OPTIONS_DISABLED` | CWE-1021 | ⚠️ Warning | `X-Frame-Options` disabled — clickjacking risk |
| `SPRING_SEC_JWT_MISSING_STATELESS_SESSION` | CWE-384 | ⚠️ Warning | JWT filter detected but `SessionCreationPolicy.STATELESS` not set |
| `SPRING_SEC_ACTUATOR_WILDCARD_EXPOSURE` | CWE-200 | ⚠️ Warning | `management.endpoints.web.exposure.include=*` exposes all actuator endpoints |
| `SPRING_SEC_HARDCODED_DEFAULT_PASSWORD` | CWE-256 | ⚠️ Warning | Hardcoded `spring.security.user.password` in properties file |

---

### ⚙️ Controller & Route Reconciliation

The extension automatically reconciles your `@RestController` endpoints against your `SecurityFilterChain` rules:

- Resolves full paths by combining class-level `@RequestMapping` with method-level `@GetMapping`, `@PostMapping`, etc.
- Detects endpoints with **no explicit matcher** (potentially exposed via a catch-all).
- Detects security matchers with **no matching controller** (dead configuration).
- Supports **path variables** (`/users/{id}`), **wildcards** (`/api/**`), and multi-pattern matchers (`.requestMatchers("/a", "/b")`).
- Accounts for method-level security annotations such as `@PreAuthorize`, `@Secured`, and `@RolesAllowed` when identifying protected endpoints.

Custom `access(...)` expressions are reported as **manual review required** in the simulator because static analysis cannot safely determine their runtime result.

---

### 💡 Quick Fixes & Code Actions

One-click fixes available directly in the editor:

- `.anyRequest().permitAll()` → `.anyRequest().authenticated()`
- `NoOpPasswordEncoder.getInstance()` → `new BCryptPasswordEncoder()`
- `AbstractHttpConfigurer::disable` (CSRF) → `Customizer.withDefaults()`

Also includes **CodeLens** on `@Bean SecurityFilterChain` methods and **hover tooltips** with detailed explanations on matchers and annotations.

---

### 🔇 Inline Suppressions

Suppress a specific rule on a line with a comment:

```java
// @ssi-ignore SPRING_SEC_CSRF_DISABLED: Stateless REST API — CSRF not needed
http.csrf(AbstractHttpConfigurer::disable);
```

Also supported: `// @spring-security-ignore RULE_ID`

---

## Spring Security Compatibility

| Version | Supported syntax |
|:---|:---|
| **Spring Security 6.x / Boot 3.x** | `authorizeHttpRequests`, `requestMatchers`, Lambda DSL, `AbstractHttpConfigurer::disable`, `Customizer.withDefaults()`, `@EnableMethodSecurity` |
| **Spring Security 5.x / Boot 2.x** | `authorizeRequests`, `antMatchers`, `WebSecurityConfigurerAdapter`, `csrf().disable()`, `@EnableGlobalMethodSecurity` |

---

## Configuration

In VS Code settings (`settings.json`):

```json
{
  "springSecurityInspector.enableDiagnostics": true,
  "springSecurityInspector.scanOnSave": true,
  "springSecurityInspector.enableCodeLens": true,
  "springSecurityInspector.ignorePatterns": [
    "**/test/**"
  ]
}
```

---

## Commands

| Command | ID | Description |
|:---|:---|:---|
| Spring Security: Open Security Dashboard | `spring-security-inspector.openDashboard` | Open the full dashboard with matrix and simulator |
| Spring Security: Refresh Analysis | `spring-security-inspector.refresh` | Re-run the full workspace scan |
| Spring Security: Export SARIF Report | `spring-security-inspector.exportSarif` | Export findings in SARIF format for CI tooling |

---

## License

MIT — [Houssam OUATMANI](https://github.com/Houssam-OUATMANI)
