import * as vscode from 'vscode';
import { ControllerEndpoint } from '../models/controller';
import { HttpMethod } from '../models/route';
import { offsetToLineColumn } from './javaTokenizer';

const MAPPING_ANNOTATION_VERBS: Record<string, HttpMethod> = {
	GetMapping: 'GET',
	PostMapping: 'POST',
	PutMapping: 'PUT',
	DeleteMapping: 'DELETE',
	PatchMapping: 'PATCH',
	RequestMapping: 'ANY',
};

/**
 * Extracts string literals from a Java annotation argument string.
 * Handles both simple paths "/foo" and value/path = "/foo" forms.
 */
function extractAnnotationPaths(args: string): string[] {
	const results: string[] = [];
	// value = "/path" or path = "/path"
	// or just "/path"
	const regex = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
	let m: RegExpExecArray | null;
	while ((m = regex.exec(args)) !== null) {
		results.push(m[1]);
	}
	return results;
}

/**
 * Extracts a RequestMethod verb from annotation args like method = RequestMethod.POST
 */
function extractRequestMethod(args: string): HttpMethod | null {
	const m = /method\s*=\s*(?:RequestMethod\.)?([A-Z]+)/g.exec(args);
	if (m && ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].includes(m[1])) {
		return m[1] as HttpMethod;
	}
	return null;
}

export function scanControllers(cleanedText: string, file: vscode.Uri): ControllerEndpoint[] {
	const endpoints: ControllerEndpoint[] = [];

	// Must be a controller
	if (!/@(RestController|Controller)\b/.test(cleanedText)) {
		return [];
	}

	// Find ALL class definitions (a file can have multiple inner or co-located classes)
	const classRegex = /class\s+([a-zA-Z0-9_]+)(?:[^{]*)\{/g;
	let classMatch: RegExpExecArray | null;

	while ((classMatch = classRegex.exec(cleanedText)) !== null) {
		const controllerClass = classMatch[1];
		const classBodyStart = classMatch.index + classMatch[0].length;

		// Find the text before this class to look for annotations
		const beforeClass = cleanedText.slice(0, classMatch.index);

		// Only process if this class is annotated with @RestController or @Controller
		// Look in the last ~500 chars before the class keyword (to avoid false positives)
		const annotationWindow = beforeClass.slice(Math.max(0, beforeClass.length - 500));
		if (!/@(RestController|Controller)\b/.test(annotationWindow)) {
			continue;
		}

		// Extract class-level base path from @RequestMapping
		let basePath = '';
		const classRequestMappingRegex = /@RequestMapping\s*\(([^)]*)\)/g;
		let reqMapMatch: RegExpExecArray | null;
		while ((reqMapMatch = classRequestMappingRegex.exec(annotationWindow)) !== null) {
			const paths = extractAnnotationPaths(reqMapMatch[1]);
			if (paths.length > 0) {
				basePath = paths[0]; // Use first path as base
				break;
			}
		}

		// Extract class body (find matching brace)
		let depth = 1;
		let classBodyEnd = classBodyStart;
		while (classBodyEnd < cleanedText.length && depth > 0) {
			const c = cleanedText[classBodyEnd];
			if (c === '{') {depth++;}
			else if (c === '}') {depth--;}
			classBodyEnd++;
		}
		const classBody = cleanedText.slice(classBodyStart, classBodyEnd);

		// Find all method-level mapping annotations
		// Pattern: @(GetMapping|...) optionally followed by (args)
		// Then optionally method signature until method name
		const annotationRegex = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(([^)]*)\))?/g;
		let annotMatch: RegExpExecArray | null;

		while ((annotMatch = annotationRegex.exec(classBody)) !== null) {
			const annotationName = annotMatch[1];
			const annotationArgs = annotMatch[2] || '';
			const annotOffset = annotMatch.index;

			let httpMethod: HttpMethod = MAPPING_ANNOTATION_VERBS[annotationName] || 'ANY';

			// Check for explicit RequestMethod in args (for @RequestMapping)
			const explicitVerb = extractRequestMethod(annotationArgs);
			if (explicitVerb) {
				httpMethod = explicitVerb;
			}

			// Extract paths from annotation args
			const paths = extractAnnotationPaths(annotationArgs);

			// Find the method name after the annotation
			// Look at the next ~300 chars for a method declaration pattern
			const afterAnnotation = classBody.slice(annotOffset + annotMatch[0].length, annotOffset + annotMatch[0].length + 400);
			const methodNameMatch = /(?:public|protected|private)\s+[\w<>\[\],\s]+\s+([a-zA-Z0-9_]+)\s*\(/g.exec(afterAnnotation);
			const methodName = methodNameMatch ? methodNameMatch[1] : 'endpoint';

			const absoluteOffset = classBodyStart + annotOffset;
			const lineCol = offsetToLineColumn(cleanedText, absoluteOffset);

			if (paths.length === 0) {
				// Annotation without path args = maps to base path (e.g. @PostMapping on class mapping)
				const fullPath = combinePaths(basePath, '');
				endpoints.push({
					controllerClass,
					methodName,
					httpMethod,
					path: '',
					fullPath,
					file,
					line: lineCol.line,
					column: lineCol.column,
				});
			} else {
				for (const p of paths) {
					const fullPath = combinePaths(basePath, p);
					endpoints.push({
						controllerClass,
						methodName,
						httpMethod,
						path: p,
						fullPath,
						file,
						line: lineCol.line,
						column: lineCol.column,
					});
				}
			}
		}
	}

	return endpoints;
}

export function combinePaths(base: string, sub: string): string {
	let cleanBase = base.trim();
	let cleanSub = sub.trim();

	if (!cleanBase.startsWith('/') && cleanBase.length > 0) {
		cleanBase = '/' + cleanBase;
	}
	if (cleanBase.endsWith('/')) {
		cleanBase = cleanBase.slice(0, -1);
	}

	if (!cleanSub.startsWith('/') && cleanSub.length > 0) {
		cleanSub = '/' + cleanSub;
	}

	const result = cleanBase + cleanSub;
	return result.length === 0 ? '/' : result;
}
