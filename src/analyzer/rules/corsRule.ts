import * as vscode from 'vscode';
import { SecurityFinding } from '../../models/finding';
import { SecurityComponent } from '../../models/component';
import { offsetToLineColumn } from '../javaTokenizer';

export function checkCorsRules(
	cleanedText: string,
	file: vscode.Uri
): { findings: SecurityFinding[]; components: SecurityComponent[] } {
	const findings: SecurityFinding[] = [];
	const components: SecurityComponent[] = [];

	// ── CORS wildcard + credentials ──────────────────────────────────────
	const hasWildcardOrigin =
		/\.setAllowedOrigins\s*\(\s*(?:List\.of\s*\(\s*)?"\*"/i.test(cleanedText) ||
		/\.addAllowedOrigin\s*\(\s*"\*"/i.test(cleanedText) ||
		/\.setAllowedOriginPatterns\s*\(\s*(?:List\.of\s*\(\s*)?"\*"/i.test(cleanedText) ||
		/allowedOrigins\s*\(\s*"\*"/i.test(cleanedText) ||
		/allowedOriginPatterns\s*\(\s*"\*"/i.test(cleanedText);

	const hasAllowCredentials =
		/\.setAllowCredentials\s*\(\s*true\s*\)/i.test(cleanedText) ||
		/allowCredentials\s*\(\s*true\s*\)/i.test(cleanedText);

	if (hasWildcardOrigin && hasAllowCredentials) {
		const match =
			/\.setAllowCredentials\s*\(\s*true\s*\)/i.exec(cleanedText) ||
			/allowCredentials\s*\(\s*true\s*\)/i.exec(cleanedText);
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
			recommendation: 'Browsers block wildcard origins when credentials are included. Use explicit trusted domains instead of "*".',
		});
	}

	// ── CORS enabled detection → expose as component ────────────────────
	const hasCorsEnabled =
		/\.cors\s*\(\s*(?:Customizer\.withDefaults|[a-zA-Z0-9_]+\s*->|withDefaults)/i.test(cleanedText) ||
		/\.cors\s*\(\s*\)\s*(?!\s*\.disable)/i.test(cleanedText) ||
		/CorsConfigurationSource|CorsConfiguration|@CrossOrigin/i.test(cleanedText);

	const hasCorsDisabled = /\.cors\s*\(\s*(?:[a-zA-Z0-9_]+)\s*->\s*[a-zA-Z0-9_]+\.disable\s*\(\s*\)\s*\)/i.test(cleanedText) ||
		/\.cors\s*\(\s*\)\s*\.disable\s*\(\s*\)/i.test(cleanedText);

	if (hasCorsEnabled || hasCorsDisabled) {
		// Extract allowed origins if present
		const originsMatch =
			/(?:setAllowedOrigins|addAllowedOrigin|allowedOrigins)\s*\(\s*"([^"]+)"/i.exec(cleanedText);
		const originsDetail = originsMatch ? `Origins: ${originsMatch[1]}` : hasCorsDisabled ? 'CORS disabled' : 'Custom CorsConfigurationSource';

		const corsMatch = /\.cors\s*[\s\S]{0,5}\(/i.exec(cleanedText);
		const lineCol = corsMatch ? offsetToLineColumn(cleanedText, corsMatch.index) : { line: 1, column: 1 };

		components.push({
			name: hasCorsDisabled ? 'CORS: Disabled' : 'CORS: Enabled',
			type: 'filter',
			details: originsDetail,
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	} else if (!hasCorsEnabled && !hasCorsDisabled) {
		// CORS not explicitly configured — report as info
		const hasSecurityChain = /SecurityFilterChain/i.test(cleanedText);
		if (hasSecurityChain) {
			const chainMatch = /SecurityFilterChain/i.exec(cleanedText);
			const lineCol = chainMatch ? offsetToLineColumn(cleanedText, chainMatch.index) : { line: 1, column: 1 };
			components.push({
				name: 'CORS: Not configured',
				type: 'filter',
				details: 'No explicit CORS configuration — Spring defaults apply (block cross-origin)',
				file,
				line: lineCol.line,
				column: lineCol.column,
			});
		}
	}

	// ── X-Frame-Options / Clickjacking ───────────────────────────────────
	const hasFrameOptions = /\.frameOptions\s*\(|X-Frame-Options|frameOptions/i.test(cleanedText);
	const frameDisabled = /\.frameOptions\s*\(\s*[a-zA-Z0-9_]+\s*->\s*[a-zA-Z0-9_]+\.disable\s*\(\s*\)\s*\)/i.test(cleanedText) ||
		/\.frameOptions\s*\(\s*\)\s*\.disable\s*\(\s*\)/i.test(cleanedText) ||
		/frameOptions\s*\(\s*HeadersConfigurer[^)]*disable\s*\)/i.test(cleanedText);

	const frameSameOrigin = /\.frameOptions\s*\(\s*[a-zA-Z0-9_]+\s*->\s*[a-zA-Z0-9_]+\.sameOrigin\s*\(\s*\)\s*\)/i.test(cleanedText) ||
		/\.sameOrigin\s*\(\s*\)/i.test(cleanedText);

	if (frameDisabled) {
		const match = /\.frameOptions/i.exec(cleanedText);
		const lineCol = match ? offsetToLineColumn(cleanedText, match.index) : { line: 1, column: 1 };
		findings.push({
			id: `frame-options-disabled-${file.fsPath}-${lineCol.line}`,
			message: 'X-Frame-Options is disabled — application may be vulnerable to clickjacking',
			ruleId: 'SPRING_SEC_FRAME_OPTIONS_DISABLED',
			cweId: 'CWE-1021',
			severity: 'warning',
			line: lineCol.line,
			column: lineCol.column,
			file,
			recommendation: 'Only disable X-Frame-Options if you intentionally allow your app to be embedded in iframes (e.g., for H2-console). Use sameOrigin() instead of disable() when possible.',
		});
		components.push({
			name: 'X-Frame-Options: DISABLED',
			type: 'filter',
			details: '⚠️ Clickjacking protection off — CWE-1021',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	} else if (frameSameOrigin) {
		const match = /\.frameOptions/i.exec(cleanedText);
		const lineCol = match ? offsetToLineColumn(cleanedText, match.index) : { line: 1, column: 1 };
		components.push({
			name: 'X-Frame-Options: SAMEORIGIN',
			type: 'filter',
			details: 'Iframes allowed from same origin only',
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	} else if (!hasFrameOptions) {
		const hasSecurityChain = /SecurityFilterChain/i.test(cleanedText);
		if (hasSecurityChain) {
			const chainMatch = /SecurityFilterChain/i.exec(cleanedText);
			const lineCol = chainMatch ? offsetToLineColumn(cleanedText, chainMatch.index) : { line: 1, column: 1 };
			components.push({
				name: 'X-Frame-Options: DENY (default)',
				type: 'filter',
				details: 'Spring Security default — iframes blocked',
				file,
				line: lineCol.line,
				column: lineCol.column,
			});
		}
	}

	return { findings, components };
}
