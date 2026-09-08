import * as vscode from 'vscode';
import { SecurityRoute } from '../models/route';
import { SecurityFinding } from '../models/finding';
import { SecurityComponent } from '../models/component';
import { ControllerEndpoint } from '../models/controller';
import { cleanJavaSource } from './javaTokenizer';
import { parseRoutes } from './routeParser';
import { checkCsrfRules } from './rules/csrfRule';
import { checkCatchAllRules } from './rules/catchAllRule';
import { checkShadowingRules } from './rules/shadowingRule';
import { checkPasswordEncoderRules } from './rules/passwordEncoderRule';
import { checkCorsRules } from './rules/corsRule';
import { checkSessionRules } from './rules/sessionRule';
import { detectComponents } from './componentDetector';
import { detectMethodSecurity } from './methodSecurityDetector';
import { scanControllers } from './controllerScanner';
import { extractSuppressions, filterSuppressedFindings } from './suppressions';
import { reconcileControllersAndRoutes, ReconciliationResult } from './reconciler';
import { auditPropertiesFiles } from './propertiesAuditor';

export * from './javaTokenizer';
export * from './routeParser';
export * from './componentDetector';
export * from './methodSecurityDetector';
export * from './projectDetector';
export * from './controllerScanner';
export * from './reconciler';
export * from './suppressions';
export * from './propertiesAuditor';
export * from './rules/csrfRule';
export * from './rules/catchAllRule';
export * from './rules/shadowingRule';
export * from './rules/passwordEncoderRule';
export * from './rules/corsRule';
export * from './rules/sessionRule';

export interface FileAnalysisResult {
	routes: SecurityRoute[];
	endpoints: ControllerEndpoint[];
	findings: SecurityFinding[];
	components: SecurityComponent[];
}

/**
 * Analyzes a single Java file.
 */
export function analyzeJavaFile(sourceCode: string, file: vscode.Uri): FileAnalysisResult {
	const { cleanedText } = cleanJavaSource(sourceCode);

	// Check if this file relates to security, controllers or beans
	const isRelevant =
		/SecurityFilterChain|HttpSecurity|WebSecurityConfigurerAdapter|requestMatchers|antMatchers|csrf|PasswordEncoder|UserDetailsService|AuthenticationProvider|OncePerRequestFilter|PreAuthorize|Secured|RolesAllowed|RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping/.test(
			cleanedText
		);

	if (!isRelevant) {
		return { routes: [], endpoints: [], findings: [], components: [] };
	}

	const routes = parseRoutes(cleanedText, file);
	const endpoints = scanControllers(cleanedText, file);
	const components: SecurityComponent[] = [
		...detectComponents(cleanedText, file),
		...detectMethodSecurity(cleanedText, file),
	];

	const rawFindings: SecurityFinding[] = [
		...checkCsrfRules(cleanedText, file),
		...checkCatchAllRules(cleanedText, file),
		...checkPasswordEncoderRules(cleanedText, file),
		...checkCorsRules(cleanedText, file),
		...checkSessionRules(cleanedText, file),
	];

	// Filter findings that have inline suppressions like // @ssi-ignore
	const suppressions = extractSuppressions(sourceCode);
	const findings = filterSuppressedFindings(rawFindings, suppressions);

	return { routes, endpoints, findings, components };
}

/**
 * Runs cross-file rules (route shadowing, controller reconciliation, and properties audit).
 */
export async function analyzeCrossFileRules(
	routes: SecurityRoute[],
	endpoints: ControllerEndpoint[]
): Promise<{ crossFindings: SecurityFinding[]; reconciliation: ReconciliationResult }> {
	const shadowingFindings = checkShadowingRules(routes);
	const reconciliation = reconcileControllersAndRoutes(endpoints, routes);
	const propertiesFindings = await auditPropertiesFiles();

	const crossFindings = [
		...shadowingFindings,
		...reconciliation.findings,
		...propertiesFindings,
	];

	return { crossFindings, reconciliation };
}
