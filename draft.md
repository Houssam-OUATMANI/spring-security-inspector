L'extension analyse :

.authorizeHttpRequests(auth -> auth
    .requestMatchers("/auth/**").permitAll()
    .anyRequest().authenticated()
)

et affiche :

SECURITY ROUTES

/public/**          PUBLIC
/auth/**            PUBLIC
/admin/**           🔐 AUTHENTICATED
/**                  🔐 AUTHENTICATED

Et pourrait détecter des choses comme :

⚠ /admin/users is accessible through another matcher

⚠ CSRF disabled

⚠ Endpoint exposes entity directly



ajouter sa propre icône dans l'Activity Bar:
en cliquant dessus, on  pourrait ouvrir une View Container dédiée :


SPRING SECURITY
────────────────────

🛡 Security Overview

Authentication
  ├─ UserDetailsService
  ├─ PasswordEncoder
  └─ AuthenticationProvider

Authorization
  ├─ Roles
  ├─ Authorities
  └─ Request Matchers

Security Filter Chain
  ├─ CsrfFilter
  ├─ JwtFilter
  ├─ AuthorizationFilter
  └─ ...

Endpoints
  ├─ GET  /users
  ├─ POST /auth/login
  └─ ...


  L'extension ne devrait s'activer sur les projets spring maven/gradle utiliser spring security
