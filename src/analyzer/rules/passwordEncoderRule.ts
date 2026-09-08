import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkPasswordEncoderRules(cleanedText: string, file: vscode.Uri): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// NoOpPasswordEncoder
	const noopRegex = /NoOpPasswordEncoder\s*\.\s*getInstance\s*\(\s*\)/g;
	let match: RegExpExecArray | null;
	while ((match = noopRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		findings.push({
			id: `noop-password-encoder-${file.fsPath}-${lineCol.line}`,
			message: 'NoOpPasswordEncoder is insecure: passwords are stored in plain text without hashing!',
			ruleId: 'SPRING_SEC_INSECURE_PASSWORD_ENCODER',
			cweId: 'CWE-256',
			severity: 'error',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Use BCryptPasswordEncoder or PasswordEncoderFactories.createDelegatingPasswordEncoder() instead.',
			quickFixAvailable: true,
		});
	}

	// Deprecated weak encoders
	const weakRegex = /new\s+(?:StandardPasswordEncoder|MessageDigestPasswordEncoder)\s*\(/g;
	while ((match = weakRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		findings.push({
			id: `weak-password-encoder-${file.fsPath}-${lineCol.line}`,
			message: 'Weak or deprecated PasswordEncoder detected (vulnerable to hash collision and brute force)',
			ruleId: 'SPRING_SEC_WEAK_PASSWORD_ENCODER',
			cweId: 'CWE-327',
			severity: 'warning',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Upgrade to BCryptPasswordEncoder, SCryptPasswordEncoder, or Argon2PasswordEncoder.',
		});
	}

	return findings;
}
