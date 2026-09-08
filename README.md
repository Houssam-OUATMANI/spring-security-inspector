# Spring Security Inspector

Inspecte statiquement les configurations **Spring Security**, réconcilie les contrôleurs avec vos règles d'accès et expose les failles de sécurité directement dans VS Code.

![Spring Security Inspector](icon.png)

---

## 🌟 Nouveautés de la Version 0.2.0

- 📊 **Dashboard Interactif (Webview)** : Vue pleine page avec matrice des droits, recherche en direct et KPIs.
- 🎯 **Simulateur de Droits d'Accès** : Testez instantanément l'évaluation d'une requête HTTP avec des rôles simulés.
- 🔄 **Réconciliateur Contrôleurs vs Règles** : Détecte les endpoints exposés sans protection explicite et les matchers orphelins.
- ⚙️ **Audit des Propriétés & YAML** : Signale l'exposition non sécurisée de Spring Boot Actuator et les mots de passe par défaut.
- 🛡️ **Règles CORS & Sessions** : Détecte les configurations CORS permissives dangereuses et les sessions stateful non désirées.
- 🔇 **Directives de suppression** : Possibilité d'ignorer une règle via `// @ssi-ignore RULE_ID: raison`.
- ⚡ **Status Bar Item** : Résumé interactif en direct dans la barre d'état.

---

## Fonctionnalités Clés

### 1. 📊 Dashboard Interactif & Simulateur de Requêtes
- **Tableau de Bord Pleine Page** (`Spring Security: Open Security Dashboard`) :
  - **Cartes KPI** : Nombre de règles configurées, endpoints contrôleurs détectés, alertes par sévérité.
  - **Matrice interactive** : Tableau croisant chaque endpoint de contrôleur avec la règle Spring Security qui s'y applique.
  - **Simulateur de Requête** : Choisissez une méthode (`GET`, `POST`, etc.), un chemin (`/api/admin/users`) et un rôle (`ROLE_USER`), et obtenez en temps réel le verdict d'autorisation (**ALLOWED** ou **DENIED**) avec la justification.
  - **Exports en un clic** : Générez un rapport d'audit complet au format **Markdown** ou exportez les données en **JSON**.

### 2. 🛡️ Vue d'ensemble dans l'Activity Bar
- **Navigation au clic** : Cliquez sur une route, un contrôleur, une alerte ou un bean pour naviguer directement au fichier et à la ligne exacte.
- **Routes & Contrôle d'accès** : Verbes HTTP (`[GET]`, `[POST]`, `[ANY]`), patterns d'URL, statuts visuels (`permitAll` en vert, `authenticated` en jaune, `hasRole` en bleu, etc.).
- **Composants d'authentification réels** : Détection des beans `PasswordEncoder` (`BCrypt`, `Argon2`, `NoOp`), `UserDetailsService` et `AuthenticationProvider`.
- **Filtres de sécurité** : Détection des filtres personnalisés (`.addFilterBefore/After`, `OncePerRequestFilter`).
- **Sécurité au niveau méthode** : Détection de `@EnableMethodSecurity` et des annotations `@PreAuthorize`, `@Secured`, `@RolesAllowed`.

### 3. ⚠️ Moteur de Détection des Vulnérabilités (OWASP & CWE)
- **Endpoints non protégés (CWE-284)** : Alerte lorsqu'un contrôleur expose un endpoint qui ne match aucun filtre explicite et hérite d'un catch-all trop permissif.
- **Masquage de routes / Conflit de précédence (CWE-698)** : Alerte lorsqu'une règle englobante (`/**` ou `/api/**`) est placée avant une règle restrictive.
- **CSRF désactivé (CWE-352)** : Détection des syntaxes lambdas (`csrf -> csrf.disable()`), références de méthodes (`AbstractHttpConfigurer::disable`), et syntaxe Spring 5.
- **Accès public universel (CWE-284)** : Alerte sur `.anyRequest().permitAll()`.
- **Mots de passe en clair (CWE-256 / CWE-327)** : Alerte sur `NoOpPasswordEncoder.getInstance()` et sur les mots de passe par défaut dans `application.properties` / `application.yml`.
- **CORS Permissif dangereux (CWE-942)** : Alerte en cas de `allowedOrigins("*")` combiné avec `allowCredentials(true)`.
- **Exposition Actuator (CWE-200)** : Alerte si `management.endpoints.web.exposure.include=*` expose les endpoints de management sans restriction.
- **Session Stateful sur API Token (CWE-384)** : Alerte lorsqu'un filtre JWT est présent sans `SessionCreationPolicy.STATELESS`.

### 4. 💡 Quick Fixes (Code Actions) & Ergonomie
- **Corrections rapides en un clic** :
  - Remplacement de `.anyRequest().permitAll()` par `.anyRequest().authenticated()`.
  - Remplacement de `NoOpPasswordEncoder.getInstance()` par `new BCryptPasswordEncoder()`.
  - Remplacement de `AbstractHttpConfigurer::disable` par `Customizer.withDefaults()`.
- **CodeLens interactif** sur les beans `@Bean SecurityFilterChain`.
- **Hover Provider** : Infobulles explicatives détaillées au survol des règles et annotations.
- **Status Bar** : Affichage discret du statut en direct.

---

## Directives de Suppression (`@ssi-ignore`)

Pour ignorer légitimement une règle sans désactiver l'extension, ajoutez un commentaire au-dessus ou sur la ligne concernée :

```java
// @ssi-ignore SPRING_SEC_CSRF_DISABLED: Stateless REST API with JWT tokens
http.csrf(AbstractHttpConfigurer::disable);
```

---

## Compatibilité Spring Security

| Version | Syntaxes supportées |
| :--- | :--- |
| **Spring Security 6.x / Boot 3.x** | `authorizeHttpRequests`, `requestMatchers`, Lambdas DSL, `AbstractHttpConfigurer::disable`, `Customizer.withDefaults()`, `@EnableMethodSecurity` |
| **Spring Security 5.x / Boot 2.x** | `authorizeRequests`, `antMatchers`, `WebSecurityConfigurerAdapter`, `csrf().disable()`, `@EnableGlobalMethodSecurity` |

---

## Configuration

Dans vos paramètres VS Code (`settings.json`) :

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

## Commandes

- `Spring Security: Open Security Dashboard` (`spring-security-inspector.openDashboard`) : Ouvre la matrice et le simulateur.
- `Spring Security: Refresh Analysis` (`spring-security-inspector.refresh`) : Relance l'analyse complète.
