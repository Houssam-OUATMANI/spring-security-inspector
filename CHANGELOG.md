# Change Log

All notable changes to **Spring Security Inspector** are documented in this file.

## [0.1.0] - 2026-09-08

### Added

#### 📊 Interactive Security Dashboard (Webview)
- Full-page dashboard opened via `Spring Security: Open Security Dashboard`.
- **KPI cards**: total security matchers, controller endpoints, findings by severity, detected Spring Security version.
- **Access Control Matrix**: cross-references every `@RestController` endpoint with its matched Spring Security rule — filterable by path/method/controller and by access level. Displays per-row result count.
- **Request Authorization Simulator**: select HTTP method, path, and user roles — get an instant **ALLOWED / DENIED** verdict with the matched rule and reason. Logic runs fully client-side against the real parsed security configuration (supports `permitAll`, `denyAll`, `authenticated`, `hasRole`, `hasAnyRole`, `hasAuthority`, `hasAnyAuthority`, role normalization `USER` → `ROLE_USER`).
- **Findings tab**: all detected issues ranked by severity, with CWE identifiers and file:line location.
- **One-click exports**: full audit report as **Markdown** or raw data as **JSON**.

#### 🌲 Security Overview (Activity Bar)
- Structured tree view of the entire Spring Security configuration:
  - **Security Rules**: HTTP method, URL pattern, and access level with semantic icons (`🔓 Public`, `🔑 Auth Required`, `🛡 Role Required`, `⛔ Deny All`).
  - **Controller Endpoints**: all `@RestController` / `@Controller` methods with their resolved full path.
  - **Security Findings**: sorted by severity (errors first), with rich Markdown tooltips including clickable CWE links and recommendations.
  - **Authentication**: `PasswordEncoder` (BCrypt, Argon2, NoOp), `UserDetailsService`, `AuthenticationProvider` beans.
  - **Filter Chain**: custom filters, **Session Policy** (`STATELESS` / `ALWAYS` / `NEVER` / `IF_REQUIRED`), **CORS configuration** (enabled/disabled/origins), **X-Frame-Options** status.
  - **Method Security**: `@PreAuthorize`, `@Secured`, `@RolesAllowed` annotations.
- Click any item to navigate directly to the exact file and line in the editor.

#### 🔍 Vulnerability Detection Engine (OWASP / CWE)
- **`SPRING_SEC_UNPROTECTED_ENDPOINT`** (CWE-284, warning): controller endpoint matched by no explicit security matcher.
- **`SPRING_SEC_ENDPOINT_EXPOSED_VIA_CATCHALL`** (CWE-284, error): endpoint accessible via generic `/**` permitAll catch-all.
- **`SPRING_SEC_DEAD_MATCHER`** (info): security matcher with no corresponding controller endpoint.
- **`SPRING_SEC_ROUTE_SHADOWED`** (CWE-698, warning): broader rule placed before a more restrictive specific rule.
- **`SPRING_SEC_CSRF_DISABLED`** (CWE-352, warning): CSRF protection disabled without `SessionCreationPolicy.STATELESS`.
- **`SPRING_SEC_CSRF_DISABLED_STATELESS`** (CWE-352, info): CSRF disabled with `STATELESS` session — acceptable for JWT APIs.
- **`SPRING_SEC_CSRF_IGNORED_ROUTES`** (CWE-352, info): CSRF selectively disabled via `ignoringRequestMatchers`.
- **`SPRING_SEC_CATCH_ALL_PERMIT`** (CWE-284, error): `.anyRequest().permitAll()` makes everything public.
- **`SPRING_SEC_NOOPENCODER`** (CWE-256, error): `NoOpPasswordEncoder` stores passwords as plain text.
- **`SPRING_SEC_CORS_WILDCARD_CREDENTIALS`** (CWE-942, error): `allowedOrigins("*")` combined with `allowCredentials(true)`.
- **`SPRING_SEC_FRAME_OPTIONS_DISABLED`** (CWE-1021, warning): `X-Frame-Options` explicitly disabled — clickjacking risk.
- **`SPRING_SEC_JWT_MISSING_STATELESS_SESSION`** (CWE-384, warning): JWT filter present without `SessionCreationPolicy.STATELESS`.
- **`SPRING_SEC_ACTUATOR_WILDCARD_EXPOSURE`** (CWE-200, warning): `management.endpoints.web.exposure.include=*` in properties.
- **`SPRING_SEC_HARDCODED_DEFAULT_PASSWORD`** (CWE-256, warning): hardcoded `spring.security.user.password` in properties file.

#### 🔄 Controller & Route Reconciliation Engine
- Scans `@RestController` and `@Controller` classes, resolving full paths by combining class-level `@RequestMapping` with method-level `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`.
- Supports path variables (`/users/{id}`), wildcards (`/api/**`), and multi-pattern matchers (`.requestMatchers("/a", "/b")`).
- Brace-matching class body extraction to correctly handle multiple classes per file.

#### ⚙️ Properties & YAML Auditor
- Audits `application.properties`, `application.yml`, and `application.yaml`.
- Flags wildcard Actuator exposure and hardcoded plain-text passwords.

#### 💡 Quick Fixes & Code Actions
- `.anyRequest().permitAll()` → `.anyRequest().authenticated()`
- `NoOpPasswordEncoder.getInstance()` → `new BCryptPasswordEncoder()`
- `AbstractHttpConfigurer::disable` → `Customizer.withDefaults()`
- **CodeLens** on `@Bean SecurityFilterChain` beans.
- **Hover tooltips** with detailed explanations on matchers and security annotations.

#### 🔇 Inline Suppressions
- `// @ssi-ignore RULE_ID: reason` — suppress a finding on a specific line.
- `// @spring-security-ignore RULE_ID` — alternative syntax.

#### ⚡ Status Bar
- Live status bar item: `$(shield) Spring Sec: X routes (Y alerts)` — click to open the dashboard.

#### 🧪 Test Suite
- 17 unit and integration tests covering: route parsing, CSRF/CORS/session rules, controller scanning, route reconciliation, request simulation, and inline suppressions.

#### Spring Security Compatibility
- **Spring Security 6.x / Boot 3.x**: `authorizeHttpRequests`, `requestMatchers`, Lambda DSL, `AbstractHttpConfigurer::disable`, `@EnableMethodSecurity`.
- **Spring Security 5.x / Boot 2.x**: `authorizeRequests`, `antMatchers`, `WebSecurityConfigurerAdapter`, `csrf().disable()`, `@EnableGlobalMethodSecurity`.