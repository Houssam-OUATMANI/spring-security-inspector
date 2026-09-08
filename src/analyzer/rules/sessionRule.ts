import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { SecurityComponent } from '../../models/component';
import { offsetToLineColumn } from '../javaTokenizer';

export type SessionPolicy = 'STATELESS' | 'ALWAYS' | 'NEVER' | 'IF_REQUIRED' | 'unknown';

export interface SessionInfo {
	policy: SessionPolicy;
	line: number;
	column: number;
}

/**
 * Extracts the SessionCreationPolicy from the source text, if declared.
 */
export function detectSessionPolicy(cleanedText: string): SessionInfo {
	const policyRegex = /SessionCreationPolicy\s*\.\s*(STATELESS|ALWAYS|NEVER|IF_REQUIRED)/g;
	const match = policyRegex.exec(cleanedText);
	if (match) {
		const lc = offsetToLineColumn(cleanedText, match.index);
		return { policy: match[1] as SessionPolicy, line: lc.line, column: lc.column };
	}
	return { policy: 'unknown', line: 0, column: 0 };
}

export function checkSessionRules(
	cleanedText: string,
	file: vscode.Uri
): { findings: SecurityFinding[]; components: SecurityComponent[] } {
	const findings: SecurityFinding[] = [];
	const components: SecurityComponent[] = [];

	const hasSecurityChain = /SecurityFilterChain/i.test(cleanedText);
	if (!hasSecurityChain) {
		return { findings, components };
	}

	const sessionInfo = detectSessionPolicy(cleanedText);

	// Expose session policy as an info component for the dashboard
	if (sessionInfo.policy !== 'unknown') {
		const policyDescriptions: Record<SessionPolicy, string> = {
			STATELESS: 'No HTTP session created — ideal for JWT/token APIs',
			ALWAYS: 'Session always created — stateful app',
			NEVER: 'Session never created but will use existing if present',
			IF_REQUIRED: 'Session created only if required (Spring default)',
			unknown: '',
		};
		components.push({
			name: `Session Policy: ${sessionInfo.policy}`,
			type: 'filter',
			details: policyDescriptions[sessionInfo.policy],
			file,
			line: sessionInfo.line,
			column: sessionInfo.column,
		});
	}

	// Warn if JWT filter is used but session is not STATELESS
	const hasJwtFilter = /Jwt|JWT|TokenAuthenticationFilter|OncePerRequestFilter/i.test(cleanedText);
	if (hasJwtFilter && sessionInfo.policy !== 'STATELESS') {
		const match = /SecurityFilterChain/i.exec(cleanedText);
		const lineCol = match ? offsetToLineColumn(cleanedText, match.index) : { line: 1, column: 1 };
		findings.push({
			id: `jwt-stateful-session-${file.fsPath}-${lineCol.line}`,
			message: 'Token-based JWT filter detected without explicit SessionCreationPolicy.STATELESS',
			ruleId: 'SPRING_SEC_JWT_MISSING_STATELESS_SESSION',
			cweId: 'CWE-384',
			severity: 'warning',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Add http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) to prevent unexpected HTTP session creation.',
		});
	}

	return { findings, components };
}
