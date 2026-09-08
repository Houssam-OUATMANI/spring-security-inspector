import { SecurityFinding } from '../../models/finding';
import { SecurityRoute } from '../../models/route';

export function checkShadowingRules(routes: SecurityRoute[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Group routes by file
	const routesByFile = new Map<string, SecurityRoute[]>();
	for (const route of routes) {
		const key = route.file.toString();
		if (!routesByFile.has(key)) {
			routesByFile.set(key, []);
		}
		routesByFile.get(key)!.push(route);
	}

	for (const [, fileRoutes] of routesByFile) {
		// Compare each route with subsequent routes
		for (let i = 0; i < fileRoutes.length; i++) {
			const earlier = fileRoutes[i];
			// ignore anyRequest() in earlier check because anyRequest() should be at the end
			if (earlier.pattern.includes('anyRequest')) {
				continue;
			}

			for (let j = i + 1; j < fileRoutes.length; j++) {
				const later = fileRoutes[j];
				if (later.pattern.includes('anyRequest')) {
					continue;
				}

				// Check method compatibility: earlier ANY matches everything, or both methods match
				const methodMatches = earlier.method === 'ANY' || earlier.method === later.method;
				if (!methodMatches) {
					continue;
				}

				if (doesSubsume(earlier.pattern, later.pattern)) {
					const isLaterMoreRestrictive =
						earlier.accessLevel === 'permitAll' && later.accessLevel !== 'permitAll';

					const severity = isLaterMoreRestrictive ? 'error' : 'warning';
					const message = isLaterMoreRestrictive
						? `Security Bypass: Route '${later.pattern}' (${later.accessLevel}) is shadowed by earlier permissive route '${earlier.pattern}' (line ${earlier.line})`
						: `Route conflict: '${later.pattern}' is shadowed by earlier route '${earlier.pattern}' (line ${earlier.line}) and will never be evaluated`;

					findings.push({
						id: `route-shadowed-${later.file.fsPath}-${later.line}-${later.pattern}`,
						message,
						ruleId: 'SPRING_SEC_ROUTE_SHADOWED',
						cweId: 'CWE-698', // Execution After Redirect and Resource Locking Issues / Precedence
						severity,
						line: later.line,
						column: later.column,
						file: later.file,
						recommendation: `In Spring Security, the first matching rule wins. Move '${later.pattern}' before '${earlier.pattern}' to ensure proper evaluation.`,
					});
				}
			}
		}
	}

	return findings;
}

function doesSubsume(pattern1: string, pattern2: string): boolean {
	if (pattern1 === pattern2) {
		return true;
	}
	if (pattern1 === '/**') {
		return true;
	}
	if (pattern1.endsWith('/**')) {
		const prefix = pattern1.slice(0, -3); // e.g. "/api"
		if (pattern2.startsWith(prefix + '/') || pattern2 === prefix) {
			return true;
		}
	}
	if (pattern1.endsWith('/*')) {
		const prefix = pattern1.slice(0, -2);
		if (pattern2.startsWith(prefix + '/')) {
			const remainder = pattern2.slice(prefix.length + 1);
			if (!remainder.includes('/')) {
				return true;
			}
		}
	}
	return false;
}
