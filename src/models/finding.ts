import * as vscode from 'vscode';

export type FindingSeverity = 'info' | 'warning' | 'error';

export interface SecurityFinding {
	id: string;
	message: string;
	ruleId: string;
	cweId?: string;
	severity: FindingSeverity;
	line: number;
	column?: number;
	endLine?: number;
	endColumn?: number;
	file: vscode.Uri;
	recommendation?: string;
	quickFixAvailable?: boolean;
}
