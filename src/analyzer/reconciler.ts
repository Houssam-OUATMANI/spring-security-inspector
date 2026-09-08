import { ControllerEndpoint } from '../models/controller';
import { SecurityRoute, HttpMethod } from '../models/route';
import { SecurityFinding } from '../models/finding';

export interface ReconciliationResult {
	findings: SecurityFinding[];
	endpointMatches: Map<ControllerEndpoint, SecurityRoute | null>;
}

export function reconcileControllersAndRoutes(
	endpoints: ControllerEndpoint[],
	routes: SecurityRoute[]
): ReconciliationResult {
	const findings: SecurityFinding[] = [];
	const endpointMatches = new Map<ControllerEndpoint, SecurityRoute | null>();
	const matchedRouteIndices = new Set<number>();

	for (const endpoint of endpoints) {
		let matchedRoute: SecurityRoute | null = null;

		for (let i = 0; i < routes.length; i++) {
			const route = routes[i];

			// Method match
			const methodMatch = route.method === 'ANY' || route.method === endpoint.httpMethod;
			if (!methodMatch) {
				continue;
			}

			// Path match
			if (matchesPattern(route.pattern, endpoint.fullPath)) {
				matchedRoute = route;
				matchedRouteIndices.add(i);
				break; // First match wins in Spring Security
			}
		}

		endpointMatches.set(endpoint, matchedRoute);

		if (!matchedRoute) {
			// No matcher matched at all
			findings.push({
				id: `unprotected-endpoint-${endpoint.file.fsPath}-${endpoint.line}`,
				message: `Unmatched endpoint: [${endpoint.httpMethod}] ${endpoint.fullPath} has no explicit security matcher`,
				ruleId: 'SPRING_SEC_UNPROTECTED_ENDPOINT',
				cweId: 'CWE-284',
				severity: 'warning',
				line: endpoint.line,
				column: endpoint.column,
				file: endpoint.file,
				recommendation: `Add an explicit requestMatcher for '${endpoint.fullPath}' in your SecurityFilterChain to prevent accidental exposure.`,
			});
		} else if (matchedRoute.accessLevel === 'permitAll' && !isExplicitPublicPath(endpoint.fullPath)) {
			// Caught by a generic permitAll (like /**)
			if (matchedRoute.pattern === '/**' || matchedRoute.pattern.includes('anyRequest')) {
				findings.push({
					id: `unprotected-endpoint-generic-${endpoint.file.fsPath}-${endpoint.line}`,
					message: `Potentially exposed endpoint: [${endpoint.httpMethod}] ${endpoint.fullPath} is public via generic '${matchedRoute.pattern}' permitAll()`,
					ruleId: 'SPRING_SEC_ENDPOINT_EXPOSED_VIA_CATCHALL',
					cweId: 'CWE-284',
					severity: 'error',
					line: endpoint.line,
					column: endpoint.column,
					file: endpoint.file,
					recommendation: `Ensure '${endpoint.fullPath}' was intended to be public, or restrict it with an explicit matcher before the catch-all.`,
				});
			}
		}
	}

	// Detect Dead Matchers (routes configured that don't match any controller)
	for (let i = 0; i < routes.length; i++) {
		const route = routes[i];
		// Skip generic catch-all patterns
		if (route.pattern === '/**' || route.pattern === '/*' || route.pattern.includes('anyRequest')) {
			continue;
		}

		if (!matchedRouteIndices.has(i) && endpoints.length > 0) {
			findings.push({
				id: `dead-matcher-${route.file.fsPath}-${route.line}-${route.pattern}`,
				message: `Dead matcher: '${route.pattern}' matches no controller endpoints in the project`,
				ruleId: 'SPRING_SEC_DEAD_MATCHER',
				severity: 'info',
				line: route.line,
				column: route.column,
				file: route.file,
				recommendation: `Verify if this URL pattern is handled by a static resource, external filter, or if the controller was deleted.`,
			});
		}
	}

	return { findings, endpointMatches };
}

export function matchesPattern(pattern: string, path: string): boolean {
	if (pattern === '/**' || pattern.includes('anyRequest')) {
		return true;
	}

	// Normalize
	const normPattern = normalizePath(pattern);
	const normPath = normalizePath(path);

	if (normPattern === normPath) {
		return true;
	}

	// Replace {id} or {param:...} with wildcard regex
	const regexPattern = normPattern
		.replace(/\{[^}]+\}/g, '[^/]+')
		.replace(/\/\*\*/g, '(?:/.*)?')
		.replace(/\/\*/g, '/[^/]+');

	const regex = new RegExp(`^${regexPattern}$`);
	return regex.test(normPath);
}

function normalizePath(p: string): string {
	let res = p.trim();
	if (!res.startsWith('/')) {
		res = '/' + res;
	}
	if (res.endsWith('/') && res.length > 1) {
		res = res.slice(0, -1);
	}
	return res;
}

function isExplicitPublicPath(path: string): boolean {
	const lower = path.toLowerCase();
	return (
		lower.includes('/public') ||
		lower.includes('/auth') ||
		lower.includes('/login') ||
		lower.includes('/register') ||
		lower.includes('/swagger') ||
		lower.includes('/v3/api-docs')
	);
}

export interface SimulationResult {
	allowed: boolean;
	matchedRoute: SecurityRoute | null;
	reason: string;
}

/**
 * Simulates a request evaluation through the Spring Security matcher chain.
 */
export function simulateRequest(
	method: HttpMethod,
	path: string,
	userRoles: string[],
	routes: SecurityRoute[]
): SimulationResult {
	for (const route of routes) {
		const methodMatch = route.method === 'ANY' || route.method === method;
		if (!methodMatch) {
			continue;
		}

		if (matchesPattern(route.pattern, path)) {
			switch (route.accessLevel) {
				case 'permitAll':
				case 'anonymous':
					return {
						allowed: true,
						matchedRoute: route,
						reason: `Explicitly allowed by rule '${route.pattern}' (permitAll)`,
					};
				case 'denyAll':
					return {
						allowed: false,
						matchedRoute: route,
						reason: `Explicitly denied by rule '${route.pattern}' (denyAll)`,
					};
				case 'authenticated':
				case 'fullyAuthenticated':
					const isAuthenticated = userRoles.length > 0;
					return {
						allowed: isAuthenticated,
						matchedRoute: route,
						reason: isAuthenticated
							? `Allowed: User is authenticated with roles [${userRoles.join(', ')}]`
							: `Denied: Endpoint requires authentication`,
					};
				case 'hasRole':
				case 'hasAnyRole':
					const requiredRoles = (route.requiredRolesOrAuthorities || []).map(r =>
						r.startsWith('ROLE_') ? r : `ROLE_${r}`
					);
					const normalizedUserRoles = userRoles.map(r => (r.startsWith('ROLE_') ? r : `ROLE_${r}`));
					const hasRequiredRole = requiredRoles.some(r => normalizedUserRoles.includes(r));
					return {
						allowed: hasRequiredRole,
						matchedRoute: route,
						reason: hasRequiredRole
							? `Allowed: User has required role [${requiredRoles.join(', ')}]`
							: `Denied: User roles [${userRoles.join(', ')}] do not satisfy required [${requiredRoles.join(', ')}]`,
					};
				case 'hasAuthority':
				case 'hasAnyAuthority':
					const requiredAuths = route.requiredRolesOrAuthorities || [];
					const hasAuth = requiredAuths.some(a => userRoles.includes(a));
					return {
						allowed: hasAuth,
						matchedRoute: route,
						reason: hasAuth
							? `Allowed: User has required authority [${requiredAuths.join(', ')}]`
							: `Denied: User authorities do not satisfy [${requiredAuths.join(', ')}]`,
					};
				default:
					return {
						allowed: true,
						matchedRoute: route,
						reason: `Allowed by custom condition: ${route.accessLevel}`,
					};
			}
		}
	}

	return {
		allowed: false,
		matchedRoute: null,
		reason: 'No rule matched: Request denied by Spring Security default policy',
	};
}
