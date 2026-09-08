import * as vscode from 'vscode';
import { SecurityComponent } from '../models/component';
import { offsetToLineColumn } from './javaTokenizer';

export function detectMethodSecurity(cleanedText: string, file: vscode.Uri): SecurityComponent[] {
	const components: SecurityComponent[] = [];

	// Match @PreAuthorize("..."), @PostAuthorize("..."), @Secured("..."), @RolesAllowed("...")
	// Properly handles single quotes inside double quotes like @PreAuthorize("hasRole('ADMIN')")
	const annotationRegex = /@(PreAuthorize|PostAuthorize|Secured|RolesAllowed)\s*\(\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')\s*\)(?:[\s\S]*?(?:public|protected|private)\s+[\w<>[\]]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\))?/g;

	let match: RegExpExecArray | null;
	while ((match = annotationRegex.exec(cleanedText)) !== null) {
		const annotationType = match[1];
		const expression = match[2] ?? match[3] ?? '';
		const methodName = match[4] || 'securedMethod';
		const lineCol = offsetToLineColumn(cleanedText, match.index);

		components.push({
			type: 'methodSecurity',
			name: `${methodName}()`,
			details: `@${annotationType}("${expression}")`,
			file,
			line: lineCol.line,
			column: lineCol.column,
		});
	}

	return components;
}
