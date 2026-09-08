import * as vscode from 'vscode';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD' | 'ANY';

export type AccessLevel =
	| 'permitAll'
	| 'authenticated'
	| 'anonymous'
	| 'denyAll'
	| 'hasRole'
	| 'hasAnyRole'
	| 'hasAuthority'
	| 'hasAnyAuthority'
	| 'rememberMe'
	| 'fullyAuthenticated'
	| 'custom';

export interface SecurityRoute {
	method: HttpMethod;
	pattern: string;
	accessLevel: AccessLevel;
	requiredRolesOrAuthorities?: string[];
	file: vscode.Uri;
	line: number;
	column: number;
	rawDeclaration?: string;
}
