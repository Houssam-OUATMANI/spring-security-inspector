# Change Log

All notable changes to the "spring-security-inspector" extension will be documented in this file.

## [0.1.0] - 2026-09-08

### Added
- **Interactive Security Dashboard (Webview)**:
  - KPI overview cards: Total Routes, Controller Endpoints, Alerts by severity, and Spring framework version.
  - Interactive searchable & filterable Security Matrix table reconciling each endpoint with its security rule.
  - Integrated **Request Authorization Simulator**: test incoming requests with simulated roles and get instantaneous verdicts (ALLOW/DENY).
  - One-click export to **Markdown** report and **JSON** dataset.
- **Controller Scanner & Reconciliation Engine**:
  - Automatically scans `@RestController` and `@Controller` mapping annotations (`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@RequestMapping`).
  - Detects **Unprotected Endpoints** (`SPRING_SEC_UNPROTECTED_ENDPOINT`) lacking explicit security rules.
  - Detects **Dead Matchers** (`SPRING_SEC_DEAD_MATCHER`) protecting non-existent URLs.
- **Properties & YAML Auditor**:
  - Audits `application.properties` and `application.yml`/`.yaml`.
  - Flags wildcard Actuator exposure (`SPRING_SEC_ACTUATOR_WILDCARD_EXPOSURE` - CWE-200).
  - Flags hardcoded plain-text passwords (`SPRING_SEC_HARDCODED_DEFAULT_PASSWORD` - CWE-256).
- **Advanced Security Rules**:
  - Insecure CORS detection: `allowedOrigins("*")` with credentials (`SPRING_SEC_CORS_WILDCARD_CREDENTIALS` - CWE-942).
  - Stateless session check for token-based JWT filter chains (`SPRING_SEC_JWT_MISSING_STATELESS_SESSION` - CWE-384).
- **Inline Suppressions**:
  - Support for `// @ssi-ignore RULE_ID: reason` and `// @spring-security-ignore RULE_ID` to silence documented exemptions.
- **Status Bar Integration**:
  - Live status bar item: `$(shield) Spring Sec: X routes (Y alerts)` with direct click to open dashboard.
- **Extended Test Suite**:
  - 17 unit and integration tests covering reconciliation, simulator, CORS, sessions, and suppressions.

- **Interactive TreeView**: Clickable items navigating directly to the exact file and line in the editor.
- **Visual Design**: Themed icons and status badges for routes (`permitAll`, `authenticated`, `hasRole`, `hasAuthority`, `denyAll`).
- **Comprehensive Route Parsing**: Full support for Spring Security 6 (`requestMatchers`, lambdas) and Spring Security 5 (`antMatchers`, `authorizeRequests`).
- **Real Component Detection**: Scans and displays real beans for `PasswordEncoder` (BCrypt, Argon2, NoOp), `UserDetailsService`, `AuthenticationProvider`, custom security filters (`addFilterBefore/After`), and `@PreAuthorize` methods.
- **Vulnerability Rules Engine**:
  - Route Shadowing / Precedence conflicts (CWE-698).
  - CSRF disabled detection supporting lambdas, `AbstractHttpConfigurer::disable`, and legacy syntax (CWE-352).
  - Permissive catch-all endpoints (`anyRequest().permitAll()` and `/**` permitAll) (CWE-284).
  - Plain text and weak password encoders (`NoOpPasswordEncoder`) (CWE-256 / CWE-327).
- **VS Code Code Actions (Quick Fixes)**: One-click fixes for `anyRequest().permitAll()`, `NoOpPasswordEncoder`, and CSRF.
- **CodeLens & Hover Provider**: Interactive CodeLens on `SecurityFilterChain` beans and hover documentation on matchers and security annotations.
- **Performance**: Incremental file caching and debounced saves for smooth workspace scanning.
- **Settings**: Added configuration options for diagnostics, auto-scan on save, CodeLens, and ignore patterns.
- **Test Suite**: Comprehensive automated unit and fixture tests with 100% pass rate.