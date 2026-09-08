import * as vscode from 'vscode';
import { SecurityRoute } from './route';
import { SecurityFinding } from './finding';
import { SecurityComponent } from './component';
import { ControllerEndpoint } from './controller';

export type SpringSecurityVersion = 'spring-security-5' | 'spring-security-6' | 'unknown';

export interface SecuritySummary {
	projectDetected: boolean;
	springSecurityVersion: SpringSecurityVersion;
	routes: SecurityRoute[];
	endpoints: ControllerEndpoint[];
	findings: SecurityFinding[];
	components: SecurityComponent[];
	files: vscode.Uri[];
	scannedAt: Date;
}

export function createEmptySummary(): SecuritySummary {
	return {
		projectDetected: false,
		springSecurityVersion: 'unknown',
		routes: [],
		endpoints: [],
		findings: [],
		components: [],
		files: [],
		scannedAt: new Date(),
	};
}
