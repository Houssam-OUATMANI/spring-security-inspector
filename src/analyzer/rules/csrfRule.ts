import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkCsrfRules(cleanedText: string, file: vscode.Uri): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Spring 6 lambda: csrf -> csrf.disable() or (c) -> c.disable()
	// Spring 6.1+ method reference: AbstractHttpConfigurer::disable (inside .csrf(...))
	// Spring 5: .csrf().disable()
	const csrfDisableRegexes = [
		/\.csrf\s*\(\s*(?:[a-zA-Z0-9_]+|\([a-zA-Z0-9_,\s]*\))\s*->\s*[a-zA-Z0-9_]+\.disable\s*\(\s*\)\s*\)/g,
		/\.csrf\s*\(\s*AbstractHttpConfigurer::disable\s*\)/g,
		/\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)/g,
	];

	for (const regex of csrfDisableRegexes) {
		let match: RegExpExecArray | null;
		while ((match = regex.exec(cleanedText)) !== null) {
			const lineCol = offsetToLineColumn(cleanedText, match.index);
			findings.push({
				id: `csrf-disabled-${file.fsPath}-${lineCol.line}`,
				message: 'CSRF protection is completely disabled',
				ruleId: 'SPRING_SEC_CSRF_DISABLED',
				cweId: 'CWE-352',
				severity: 'warning',
				line: lineCol.line,
				column: lineCol.column,
				file,
				recommendation: 'Only disable CSRF for stateless REST APIs using token-based authentication (like JWT). For browser clients using cookies/sessions, keep CSRF enabled.',
				quickFixAvailable: true,
			});
		}
	}

	// Check if CSRF ignoringRequestMatchers is used
	const csrfIgnoreRegex = /\.ignoringRequestMatchers\s*\(([\s\S]*?)\)/g;
	let match: RegExpExecArray | null;
	while ((match = csrfIgnoreRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		findings.push({
			id: `csrf-ignored-${file.fsPath}-${lineCol.line}`,
			message: `CSRF protection is selectively disabled for paths in ignoringRequestMatchers: ${match[1].trim()}`,
			ruleId: 'SPRING_SEC_CSRF_IGNORED_ROUTES',
			cweId: 'CWE-352',
			severity: 'info',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Ensure these ignored paths cannot be abused by cross-site requests (e.g. state-changing actions).',
		});
	}

	return findings;
}
