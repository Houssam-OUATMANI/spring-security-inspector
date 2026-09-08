import * as vscode from 'vscode';
import { SecurityComponent } from '../models/component';
import { offsetToLineColumn } from './javaTokenizer';

export function detectComponents(cleanedText: string, file: vscode.Uri): SecurityComponent[] {
	const components: SecurityComponent[] = [];

	// 1. Detect PasswordEncoder
	const passwordEncoderRegex = /(?:@Bean[\s\S]*?)?PasswordEncoder\s+([a-zA-Z0-9_]+)\s*\([^)]*\)/g;
	let match: RegExpExecArray | null;
	while ((match = passwordEncoderRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		let details = 'PasswordEncoder';
		if (/BCryptPasswordEncoder/.test(cleanedText)) {
			details = 'BCryptPasswordEncoder';
		} else if (/Argon2PasswordEncoder/.test(cleanedText)) {
			details = 'Argon2PasswordEncoder';
		} else if (/NoOpPasswordEncoder/.test(cleanedText)) {
			details = 'NoOpPasswordEncoder (INSECURE)';
		}

		components.push({
			type: 'passwordEncoder',
			name: `PasswordEncoder (${match[1]})`,
			details,
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	// 2. Detect UserDetailsService
	const userDetailsRegex = /(?:class\s+([a-zA-Z0-9_]+)\s+implements\s+UserDetailsService|@Bean[\s\S]*?UserDetailsService\s+([a-zA-Z0-9_]+)\s*\([^)]*\))/g;
	while ((match = userDetailsRegex.exec(cleanedText)) !== null) {
		const name = match[1] || match[2];
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		components.push({
			type: 'authentication',
			name: `UserDetailsService (${name})`,
			details: 'Custom UserDetailsService',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	// 3. Detect AuthenticationProvider / AuthenticationManager
	const authProviderRegex = /(?:class\s+([a-zA-Z0-9_]+)\s+implements\s+AuthenticationProvider|@Bean[\s\S]*?AuthenticationProvider\s+([a-zA-Z0-9_]+)\s*\([^)]*\))/g;
	while ((match = authProviderRegex.exec(cleanedText)) !== null) {
		const name = match[1] || match[2];
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		components.push({
			type: 'authentication',
			name: `AuthenticationProvider (${name})`,
			details: 'Custom AuthenticationProvider',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	// 4. Detect Filter registrations via addFilterBefore/addFilterAfter/addFilterAt
	const filterRegisterRegex = /\.addFilter(Before|After|At)\s*\(\s*(?:new\s+)?([a-zA-Z0-9_]+(?:\([^)]*\))?)\s*,\s*([a-zA-Z0-9_]+)\.class\s*\)/g;
	while ((match = filterRegisterRegex.exec(cleanedText)) !== null) {
		const position = match[1]; // Before, After, At
		const filterName = match[2].split('(')[0];
		const relativeClass = match[3];
		const lineCol = offsetToLineColumn(cleanedText, match.index);

		components.push({
			type: 'filter',
			name: filterName,
			details: `addFilter${position} (${relativeClass})`,
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	// 5. Detect Classes extending OncePerRequestFilter
	const filterClassRegex = /class\s+([a-zA-Z0-9_]+)\s+extends\s+OncePerRequestFilter/g;
	while ((match = filterClassRegex.exec(cleanedText)) !== null) {
		const className = match[1];
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		components.push({
			type: 'filter',
			name: className,
			details: 'Custom OncePerRequestFilter (e.g. JWT/Auth filter)',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	// 6. Detect @EnableMethodSecurity or @EnableGlobalMethodSecurity
	const methodSecurityRegex = /@(EnableMethodSecurity|EnableGlobalMethodSecurity)(?:\s*\(([^)]*)\))?/g;
	while ((match = methodSecurityRegex.exec(cleanedText)) !== null) {
		const lineCol = offsetToLineColumn(cleanedText, match.index);
		const annotation = match[1];
		const params = match[2] ? `(${match[2].trim()})` : '';

		components.push({
			type: 'methodSecurity',
			name: `@${annotation}${params}`,
			details: 'Method-level authorization enabled',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	return components;
}
