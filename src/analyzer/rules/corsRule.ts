import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkCorsRules(cleanedText: string, file: vscode.Uri): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Check if allowedOrigins("*") or allowedOriginPatterns("*") is paired with allowCredentials(true)
	const hasWildcardOrigin = /\.setAllowedOrigins\s*\(\s*(?:List\.of\s*\(\s*)?["']\*["']/i.test(cleanedText) ||
		/\.addAllowedOrigin\s*\(\s*["']\*["']/i.test(cleanedText) ||
		/\.setAllowedOriginPatterns\s*\(\s*(?:List\.of\s*\(\s*)?["']\*["']/i.test(cleanedText);

	const hasAllowCredentials = /\.setAllowCredentials\s*\(\s*true\s*\)/i.test(cleanedText);

	if (hasWildcardOrigin && hasAllowCredentials) {
		const match = /\.setAllowCredentials\s*\(\s*true\s*\)/i.exec(cleanedText);
		const lineCol = match ? offsetToLineColumn(cleanedText, match.index) : { line: 1, column: 1 };

		findings.push({
			id: `cors-wildcard-credentials-${file.fsPath}-${lineCol.line}`,
			message: 'Dangerous CORS: wildcard origin "*" combined with allowCredentials(true)',
			ruleId: 'SPRING_SEC_CORS_WILDCARD_CREDENTIALS',
			cweId: 'CWE-942',
			severity: 'error',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Browsers block wildcard origins when credentials are included. Specify explicit trusted domains instead of "*".',
		});
	}

	return findings;
}
