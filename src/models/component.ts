import * as vscode from 'vscode';

export type SecurityComponentType = 'authentication' | 'filter' | 'passwordEncoder' | 'methodSecurity';

export interface SecurityComponent {
	type: SecurityComponentType;
	name: string;
	details?: string;
	file: vscode.Uri;
	line: number;
	column?: number;
}
