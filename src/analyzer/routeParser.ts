import * as vscode from 'vscode';
import { AccessLevel, HttpMethod, SecurityRoute } from '../models/route';
import { offsetToLineColumn } from './javaTokenizer';

const ACCESS_LEVEL_METHODS: Record<string, AccessLevel> = {
	permitAll: 'permitAll',
	authenticated: 'authenticated',
	anonymous: 'anonymous',
	denyAll: 'denyAll',
	hasRole: 'hasRole',
	hasAnyRole: 'hasAnyRole',
	hasAuthority: 'hasAuthority',
	hasAnyAuthority: 'hasAnyAuthority',
	rememberMe: 'rememberMe',
	fullyAuthenticated: 'fullyAuthenticated',
	access: 'custom',
};

const HTTP_METHOD_REGEX = /HttpMethod\.([A-Z]+)/;

export function parseRoutes(cleanedText: string, file: vscode.Uri): SecurityRoute[] {
	const routes: SecurityRoute[] = [];

	// Match (requestMatchers|antMatchers)(args).(accessMethod)(args)
	// Handles multiline chains and multiple string arguments
	const matcherRegex = /\.(requestMatchers|antMatchers)\s*\(([\s\S]*?)\)\s*\.([a-zA-Z0-9_]+)\s*\(([\s\S]*?)\)/g;

	let match: RegExpExecArray | null;
	while ((match = matcherRegex.exec(cleanedText)) !== null) {
		const matchOffset = match.index;
		const matcherArgs = match[2];
		const accessMethod = match[3];
		const accessArgs = match[4];

		const accessLevel: AccessLevel = ACCESS_LEVEL_METHODS[accessMethod] || 'custom';
		const requiredRolesOrAuthorities = extractStringLiterals(accessArgs);

		// Extract HTTP method if specified
		let httpMethod: HttpMethod = 'ANY';
		const httpMethodMatch = HTTP_METHOD_REGEX.exec(matcherArgs);
		if (httpMethodMatch && isValidHttpMethod(httpMethodMatch[1])) {
			httpMethod = httpMethodMatch[1] as HttpMethod;
		}

		// Extract path patterns
		const patterns = extractStringLiterals(matcherArgs);
		const lineCol = offsetToLineColumn(cleanedText, matchOffset);

		if (patterns.length === 0) {
			// Might be a constant or variable without quotes, or empty
			routes.push({
				method: httpMethod,
				pattern: '/*',
				accessLevel,
				requiredRolesOrAuthorities: requiredRolesOrAuthorities.length > 0 ? requiredRolesOrAuthorities : undefined,
				file,
				line: lineCol.line,
				column: lineCol.column,
				rawDeclaration: match[0].trim(),
			});
		} else {
			for (const pattern of patterns) {
				routes.push({
					method: httpMethod,
					pattern,
					accessLevel,
					requiredRolesOrAuthorities: requiredRolesOrAuthorities.length > 0 ? requiredRolesOrAuthorities : undefined,
					file,
					line: lineCol.line,
					column: lineCol.column,
					rawDeclaration: match[0].trim(),
				});
			}
		}
	}

	// Also parse .anyRequest().<accessMethod>()
	const anyRequestRegex = /\.anyRequest\s*\(\s*\)\s*\.([a-zA-Z0-9_]+)\s*\(([\s\S]*?)\)/g;
	while ((match = anyRequestRegex.exec(cleanedText)) !== null) {
		const matchOffset = match.index;
		const accessMethod = match[1];
		const accessArgs = match[2];

		const accessLevel: AccessLevel = ACCESS_LEVEL_METHODS[accessMethod] || 'custom';
		const requiredRolesOrAuthorities = extractStringLiterals(accessArgs);
		const lineCol = offsetToLineColumn(cleanedText, matchOffset);

		routes.push({
			method: 'ANY',
			pattern: '/** (anyRequest)',
			accessLevel,
			requiredRolesOrAuthorities: requiredRolesOrAuthorities.length > 0 ? requiredRolesOrAuthorities : undefined,
			file,
			line: lineCol.line,
			column: lineCol.column,
			rawDeclaration: match[0].trim(),
		});
	}

	return routes;
}

function extractStringLiterals(text: string): string[] {
	const literals: string[] = [];
	const regex = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(text)) !== null) {
		literals.push(match[1]);
	}
	return literals;
}

function isValidHttpMethod(method: string): boolean {
	return ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].includes(method);
}
