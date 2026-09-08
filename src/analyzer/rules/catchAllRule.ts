import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkCatchAllRules(cleanedText: string, file: vscode.Uri): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Check anyRequest().permitAll()
	const anyPermitRegex = /\.anyRequest\s*\(\s*\)\s*\.permitAll\s*\(\s*\)/g;
	let match: RegExpExecArray | null;
	while ((match = anyPermitRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		findings.push({
			id: `any-request-permit-all-${file.fsPath}-${lineCol.line}`,
			message: 'All unmatched endpoints are completely public via anyRequest().permitAll()',
			ruleId: 'SPRING_SEC_ANY_REQUEST_PERMIT_ALL',
			cweId: 'CWE-284',
			severity: 'error',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Use .anyRequest().authenticated() or .denyAll() as the default fallback to ensure all new endpoints are protected by default.',
			quickFixAvailable: true,
		});
	}

	// Check requestMatchers("/**").permitAll() or antMatchers("/**").permitAll()
	const catchAllPermitRegex = /\.(requestMatchers|antMatchers)\s*\(\s*(?:HttpMethod\.[A-Z]+\s*,\s*)?["']\/\*\*["']\s*\)\s*\.permitAll\s*\(\s*\)/g;
	while ((match = catchAllPermitRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		findings.push({
			id: `catch-all-permit-all-${file.fsPath}-${lineCol.line}`,
			message: "Catch-all pattern '/**' is configured with permitAll(), making the entire application public",
			ruleId: 'SPRING_SEC_CATCHALL_PERMIT_ALL',
			cweId: 'CWE-284',
			severity: 'error',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: "Specify explicit public routes (e.g. '/public/**', '/auth/**') instead of making '/**' completely open.",
			quickFixAvailable: true,
		});
	}

	return findings;
}
