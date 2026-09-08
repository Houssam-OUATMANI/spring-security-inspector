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

export function scanControllers(cleanedText: string, file: vscode.Uri): ControllerEndpoint[] {
	const endpoints: ControllerEndpoint[] = [];

	// Must be a controller
	if (!/@(RestController|Controller)\b/.test(cleanedText)) {
		return [];
	}

	// Find class definition: class ClassName ... {
	const classMatch = /class\s+([a-zA-Z0-9_]+)[\s\S]*?\{/g.exec(cleanedText);
	if (!classMatch) {
		return [];
	}

	const controllerClass = classMatch[1];
	const classStartOffset = classMatch.index;

	// Extract class-level base path from annotations before class keyword
	const beforeClass = cleanedText.slice(0, classStartOffset);
	let basePath = '';
	const classReqMatch = /@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']*)["']/g.exec(beforeClass);
	if (classReqMatch) {
		basePath = classReqMatch[1];
	}

	// Only search for method-level mappings inside the class body
	const classBody = cleanedText.slice(classStartOffset);

	const methodMappingRegex = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?(?:["']([^"']*)["']|{([^}]*)})?(?:[\s\S]*?method\s*=\s*RequestMethod\.([A-Z]+))?[^)]*\))?(?:[\s\S]*?(?:public|protected|private)\s+[\w<>[\]]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\))/g;

	let match: RegExpExecArray | null;
	while ((match = methodMappingRegex.exec(classBody)) !== null) {
		const annotation = match[1];
		let methodPath = match[2] || '';
		const multiPaths = match[3];
		const explicitVerb = match[4];
		const methodName = match[5] || 'endpoint';
		const lineCol = offsetToLineColumn(cleanedText, classStartOffset + match.index);

		let httpMethod: HttpMethod = MAPPING_ANNOTATION_VERBS[annotation] || 'ANY';
		if (explicitVerb && ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].includes(explicitVerb)) {
			httpMethod = explicitVerb as HttpMethod;
		}

		if (multiPaths) {
			const pathLiterals = extractStringLiterals(multiPaths);
			for (const p of pathLiterals) {
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
		} else {
			const fullPath = combinePaths(basePath, methodPath);
			endpoints.push({
				controllerClass,
				methodName,
				httpMethod,
				path: methodPath,
				fullPath,
				file,
				line: lineCol.line,
				column: lineCol.column,
			});
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

function extractStringLiterals(text: string): string[] {
	const literals: string[] = [];
	const regex = /["']([^"']+)["']/g;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(text)) !== null) {
		literals.push(match[1]);
	}
	return literals;
}
