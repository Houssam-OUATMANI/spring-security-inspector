import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkSessionRules(cleanedText: string, file: vscode.Uri): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Check if JWT filter is registered but session is not set to STATELESS
	const hasJwtFilter = /Jwt|JWT|TokenAuthenticationFilter|OncePerRequestFilter/i.test(cleanedText);
	const hasSecurityChain = /SecurityFilterChain/i.test(cleanedText);
	const hasStatelessSession = /SessionCreationPolicy\s*\.\s*STATELESS/i.test(cleanedText);

	if (hasSecurityChain && hasJwtFilter && !hasStatelessSession) {
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
			recommendation: 'Configure http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) to prevent unwanted HTTP session creation.',
		});
	}

	return findings;
}
