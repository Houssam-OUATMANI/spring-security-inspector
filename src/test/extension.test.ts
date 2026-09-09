import * as assert from 'assert';
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { cleanJavaSource } from '../analyzer/javaTokenizer';
import { parseRoutes } from '../analyzer/routeParser';
import { checkCsrfRules } from '../analyzer/rules/csrfRule';
import { checkCatchAllRules } from '../analyzer/rules/catchAllRule';
import { checkShadowingRules } from '../analyzer/rules/shadowingRule';
import { checkPasswordEncoderRules } from '../analyzer/rules/passwordEncoderRule';
import { checkCorsRules } from '../analyzer/rules/corsRule';
import { checkSessionRules } from '../analyzer/rules/sessionRule';
import { detectComponents } from '../analyzer/componentDetector';
import { detectMethodSecurity } from '../analyzer/methodSecurityDetector';
import { scanControllers } from '../analyzer/controllerScanner';
import { reconcileControllersAndRoutes, simulateRequest } from '../analyzer/reconciler';
import { analyzeJavaFile } from '../analyzer';

suite('Spring Security Inspector Test Suite', () => {
	const mockUri = vscode.Uri.file('/mock/TestSecurityConfig.java');

	suite('Java Tokenizer & Comment Stripper', () => {
		test('Preserves line numbers while stripping single and multiline comments', () => {
			const source = [
				'// Single line comment',
				'public class Test {',
				'    /* Multiline',
				'       comment */',
				'    String s = "// not a comment";',
				'}',
			].join('\n');

			const { cleanedText } = cleanJavaSource(source);
			const originalLines = source.split('\n');
			const cleanedLines = cleanedText.split('\n');

			assert.strictEqual(cleanedLines.length, originalLines.length);
			assert.ok(!cleanedLines[0].includes('Single line comment'));
			assert.ok(cleanedLines[1].includes('public class Test'));
			assert.ok(!cleanedLines[2].includes('Multiline'));
			assert.ok(!cleanedLines[3].includes('comment'));
			assert.ok(cleanedLines[4].includes('String s = "// not a comment";'));
		});
	});

	suite('Route Parsing', () => {
		test('Parses Spring Security 6 requestMatchers with HTTP methods and multiple patterns', () => {
			const code = `
				.authorizeHttpRequests(auth -> auth
					.requestMatchers("/public/**", "/auth/**").permitAll()
					.requestMatchers(HttpMethod.GET, "/api/products/**").permitAll()
					.requestMatchers(HttpMethod.POST, "/api/orders/**").hasRole("USER")
					.requestMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated()
				)
			`;
			const routes = parseRoutes(code, mockUri);
			assert.strictEqual(routes.length, 6);

			const publicRoute1 = routes.find(r => r.pattern === '/public/**');
			assert.ok(publicRoute1);
			assert.strictEqual(publicRoute1.accessLevel, 'permitAll');
			assert.strictEqual(publicRoute1.method, 'ANY');

			const getProductsRoute = routes.find(r => r.pattern === '/api/products/**');
			assert.ok(getProductsRoute);
			assert.strictEqual(getProductsRoute.method, 'GET');
			assert.strictEqual(getProductsRoute.accessLevel, 'permitAll');

			const postOrdersRoute = routes.find(r => r.pattern === '/api/orders/**');
			assert.ok(postOrdersRoute);
			assert.strictEqual(postOrdersRoute.method, 'POST');
			assert.strictEqual(postOrdersRoute.accessLevel, 'hasRole');
			assert.deepStrictEqual(postOrdersRoute.requiredRolesOrAuthorities, ['USER']);

			const anyRequestRoute = routes.find(r => r.pattern.includes('anyRequest'));
			assert.ok(anyRequestRoute);
			assert.strictEqual(anyRequestRoute.accessLevel, 'authenticated');
		});

		test('Parses Spring Security 5 legacy antMatchers', () => {
			const code = `
				http.authorizeRequests()
					.antMatchers("/public/**").permitAll()
					.antMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated();
			`;
			const routes = parseRoutes(code, mockUri);
			assert.strictEqual(routes.length, 3);
			assert.strictEqual(routes[0].pattern, '/public/**');
			assert.strictEqual(routes[0].accessLevel, 'permitAll');
			assert.strictEqual(routes[1].pattern, '/admin/**');
			assert.strictEqual(routes[1].accessLevel, 'hasRole');
		});
	});

	suite('Security Rules', () => {
		test('CSRF Rule detects lambda, method reference, and Spring 5 disabled syntax', () => {
			const modernMethodRef = `http.csrf(AbstractHttpConfigurer::disable);`;
			const modernLambda = `http.csrf(csrf -> csrf.disable());`;
			const legacyStyle = `http.csrf().disable();`;
			const enabledStyle = `http.csrf(Customizer.withDefaults());`;

			const findings1 = checkCsrfRules(modernMethodRef, mockUri);
			assert.strictEqual(findings1.length, 1);
			assert.strictEqual(findings1[0].ruleId, 'SPRING_SEC_CSRF_DISABLED');
			assert.strictEqual(findings1[0].cweId, 'CWE-352');

			const findings2 = checkCsrfRules(modernLambda, mockUri);
			assert.strictEqual(findings2.length, 1);

			const findings3 = checkCsrfRules(legacyStyle, mockUri);
			assert.strictEqual(findings3.length, 1);

			const findings4 = checkCsrfRules(enabledStyle, mockUri);
			assert.strictEqual(findings4.length, 0);
		});

		test('CatchAll Rule detects anyRequest().permitAll() and /** permitAll', () => {
			const insecureCode = `
				.requestMatchers("/**").permitAll()
				.anyRequest().permitAll()
			`;
			const findings = checkCatchAllRules(insecureCode, mockUri);
			assert.strictEqual(findings.length, 2);
			assert.ok(findings.some(f => f.ruleId === 'SPRING_SEC_ANY_REQUEST_PERMIT_ALL'));
			assert.ok(findings.some(f => f.ruleId === 'SPRING_SEC_CATCHALL_PERMIT_ALL'));
		});

		test('Shadowing Rule flags when broader route precedes a specific route', () => {
			const code = `
				.requestMatchers("/**").permitAll()
				.requestMatchers("/admin/**").hasRole("ADMIN")
			`;
			const routes = parseRoutes(code, mockUri);
			const findings = checkShadowingRules(routes);
			assert.strictEqual(findings.length, 1);
			assert.strictEqual(findings[0].ruleId, 'SPRING_SEC_ROUTE_SHADOWED');
			assert.ok(findings[0].message.includes('shadowed'));
		});

		test('PasswordEncoder Rule detects plain text NoOpPasswordEncoder', () => {
			const insecure = `return NoOpPasswordEncoder.getInstance();`;
			const secure = `return new BCryptPasswordEncoder();`;

			const findingsInsecure = checkPasswordEncoderRules(insecure, mockUri);
			assert.strictEqual(findingsInsecure.length, 1);
			assert.strictEqual(findingsInsecure[0].ruleId, 'SPRING_SEC_INSECURE_PASSWORD_ENCODER');

			const findingsSecure = checkPasswordEncoderRules(secure, mockUri);
			assert.strictEqual(findingsSecure.length, 0);
		});
	});

	suite('Component & Method Security Detection', () => {
		test('Detects custom filters and password encoder beans', () => {
			const code = `
				@Bean
				public PasswordEncoder passwordEncoder() {
					return new BCryptPasswordEncoder();
				}

				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
			`;
			const components = detectComponents(code, mockUri);
			assert.strictEqual(components.length, 2);
			assert.ok(components.some(c => c.type === 'passwordEncoder'));
			assert.ok(components.some(c => c.type === 'filter'));
		});

		test('Detects @PreAuthorize on controller methods', () => {
			const code = `
				@GetMapping("/admin/data")
				@PreAuthorize("hasRole('ADMIN')")
				public String getAdminData() {
					return "data";
				}
			`;
			const components = detectMethodSecurity(code, mockUri);
			assert.strictEqual(components.length, 1);
			assert.strictEqual(components[0].type, 'methodSecurity');
			assert.ok(components[0].name.includes('getAdminData'));
			assert.ok(components[0].details?.includes("hasRole('ADMIN')"));
		});
	});

	suite('End-to-End Fixture Analysis', () => {
		test('Analyzes Modern Spring Security 6 fixture correctly', () => {
			const fixturePath = path.resolve(__dirname, '../../src/test/fixtures/SecurityConfigModern.java');
			const content = fs.readFileSync(fixturePath, 'utf8');
			const uri = vscode.Uri.file(fixturePath);
			const result = analyzeJavaFile(content, uri);

			assert.ok(result.routes.length >= 4);
			assert.ok(result.findings.some(f => f.ruleId === 'SPRING_SEC_CSRF_DISABLED'));
			assert.ok(result.components.some(c => c.type === 'filter'));
			assert.ok(result.components.some(c => c.type === 'passwordEncoder'));
		});

		test('Analyzes InsecureConfig fixture correctly and flags all vulnerabilities', () => {
			const fixturePath = path.resolve(__dirname, '../../src/test/fixtures/InsecureConfig.java');
			const content = fs.readFileSync(fixturePath, 'utf8');
			const uri = vscode.Uri.file(fixturePath);
			const result = analyzeJavaFile(content, uri);

			// Should detect catchAll and NoOpPasswordEncoder
			assert.ok(result.findings.some(f => f.ruleId === 'SPRING_SEC_CATCHALL_PERMIT_ALL'));
			assert.ok(result.findings.some(f => f.ruleId === 'SPRING_SEC_ANY_REQUEST_PERMIT_ALL'));
			assert.ok(result.findings.some(f => f.ruleId === 'SPRING_SEC_INSECURE_PASSWORD_ENCODER'));

			// Cross-file shadowing rule
			const crossFindings = checkShadowingRules(result.routes);
			assert.ok(crossFindings.some(f => f.ruleId === 'SPRING_SEC_ROUTE_SHADOWED'));
		});
	});

	suite('Controller Scanning & Reconciliation', () => {
		test('Scans RestController with class base path and method mappings', () => {
			const controllerCode = `
				@RestController
				@RequestMapping("/api/v1/users")
				public class UserController {

					@GetMapping("/{id}")
					public String getUser() { return "user"; }

					@PostMapping
					public String createUser() { return "created"; }

					@DeleteMapping("/{id}")
					public void deleteUser() {}
				}
			`;
			const endpoints = scanControllers(controllerCode, mockUri);
			assert.strictEqual(endpoints.length, 3);
			assert.strictEqual(endpoints[0].fullPath, '/api/v1/users/{id}');
			assert.strictEqual(endpoints[0].httpMethod, 'GET');
			assert.strictEqual(endpoints[1].fullPath, '/api/v1/users');
			assert.strictEqual(endpoints[1].httpMethod, 'POST');
			assert.strictEqual(endpoints[2].fullPath, '/api/v1/users/{id}');
			assert.strictEqual(endpoints[2].httpMethod, 'DELETE');
		});

		test('Reconciles controllers against routes and detects unprotected endpoints', () => {
			const endpoints = [
				{
					controllerClass: 'UserController',
					methodName: 'getUser',
					httpMethod: 'GET' as const,
					path: '/api/users/{id}',
					fullPath: '/api/users/{id}',
					file: mockUri,
					line: 10,
					column: 1,
				},
				{
					controllerClass: 'AdminController',
					methodName: 'resetData',
					httpMethod: 'POST' as const,
					path: '/api/admin/reset',
					fullPath: '/api/admin/reset',
					file: mockUri,
					line: 20,
					column: 1,
				},
			];

			const routes = [
				{
					method: 'GET' as const,
					pattern: '/api/users/**',
					accessLevel: 'permitAll' as const,
					file: mockUri,
					line: 5,
					column: 1,
				},
			];

			const result = reconcileControllersAndRoutes(endpoints, routes);
			assert.ok(result.endpointMatches.get(endpoints[0]));
			assert.strictEqual(result.endpointMatches.get(endpoints[1]), null);
			assert.ok(result.findings.some(f => f.ruleId === 'SPRING_SEC_UNPROTECTED_ENDPOINT'));
		});

		test('Simulates request rights accurately', () => {
			const routes = [
				{
					method: 'GET' as const,
					pattern: '/public/**',
					accessLevel: 'permitAll' as const,
					file: mockUri,
					line: 1,
					column: 1,
				},
				{
					method: 'ANY' as const,
					pattern: '/admin/**',
					accessLevel: 'hasRole' as const,
					requiredRolesOrAuthorities: ['ADMIN'],
					file: mockUri,
					line: 2,
					column: 1,
				},
			];

			// 1. Public route
			const resPublic = simulateRequest('GET', '/public/test', [], routes);
			assert.strictEqual(resPublic.allowed, true);

			// 2. Admin route without role
			const resAdminNoRole = simulateRequest('GET', '/admin/settings', ['ROLE_USER'], routes);
			assert.strictEqual(resAdminNoRole.allowed, false);

			// 3. Admin route with role
			const resAdminWithRole = simulateRequest('POST', '/admin/settings', ['ROLE_ADMIN'], routes);
			assert.strictEqual(resAdminWithRole.allowed, true);
		});

		test('Returns an indeterminate verdict for custom access expressions', () => {
			const routes = parseRoutes('.requestMatchers("/internal/**").access(customAuthorization())', mockUri);
			const result = simulateRequest('GET', '/internal/data', ['ROLE_ADMIN'], routes);
			assert.strictEqual(result.verdict, 'unknown');
			assert.strictEqual(result.allowed, false);
		});

		test('Does not report method-secured endpoints as unprotected', () => {
			const controllerCode = `
				@RestController
				public class AdminController {
					@GetMapping("/admin")
					@PreAuthorize("hasRole('ADMIN')")
					public String admin() { return "ok"; }
				}
			`;
			const endpoints = scanControllers(controllerCode, mockUri);
			const result = reconcileControllersAndRoutes(endpoints, []);
			assert.strictEqual(endpoints[0].methodSecurity, '@PreAuthorize("hasRole(\'ADMIN\')")');
			assert.strictEqual(result.findings.length, 0);
		});
	});

	suite('Advanced Rules & Suppressions', () => {
		test('CORS rule detects wildcard with credentials', () => {
			const corsCode = `
				cors.setAllowedOrigins(List.of("*"));
				cors.setAllowCredentials(true);
			`;
			const { findings } = checkCorsRules(corsCode, mockUri);
			assert.strictEqual(findings.length, 1);
			assert.strictEqual(findings[0].ruleId, 'SPRING_SEC_CORS_WILDCARD_CREDENTIALS');
		});

		test('Session rule detects stateful session when JWT filter is used', () => {
			const code = `
				@Bean
				public SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
					http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
					return http.build();
				}
			`;
			const { findings } = checkSessionRules(code, mockUri);
			assert.strictEqual(findings.length, 1);
			assert.strictEqual(findings[0].ruleId, 'SPRING_SEC_JWT_MISSING_STATELESS_SESSION');
		});

		test('Suppression comments filter out designated findings', () => {
			const code = [
				'// @ssi-ignore SPRING_SEC_CSRF_DISABLED: Justified for stateless API',
				'http.csrf(AbstractHttpConfigurer::disable);',
			].join('\n');

			const result = analyzeJavaFile(code, mockUri);
			assert.strictEqual(result.findings.filter(f => f.ruleId === 'SPRING_SEC_CSRF_DISABLED').length, 0);
		});
	});
});

