import * as vscode from 'vscode';
import { SecuritySummary } from '../models/summary';

export class SecurityStatusBarItem implements vscode.Disposable {
	private readonly statusBarItem: vscode.StatusBarItem;

	constructor() {
		this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
		this.statusBarItem.command = 'spring-security-inspector.openDashboard';
	}

	update(summary: SecuritySummary): void {
		if (!summary.projectDetected) {
			this.statusBarItem.hide();
			return;
		}

		const routeCount = summary.routes.length;
		const findingCount = summary.findings.length;
		const errorCount = summary.findings.filter(f => f.severity === 'error').length;

		let icon = '$(shield)';
		if (errorCount > 0) {
			icon = '$(error)';
			this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
		} else if (findingCount > 0) {
			icon = '$(warning)';
			this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
		} else {
			this.statusBarItem.backgroundColor = undefined;
		}

		this.statusBarItem.text = `${icon} Spring Sec: ${routeCount} routes (${findingCount} alerts)`;
		this.statusBarItem.tooltip = new vscode.MarkdownString(
			`**Spring Security Inspector**\n\n- **Routes:** ${routeCount}\n- **Endpoints:** ${summary.endpoints.length}\n- **Alerts:** ${findingCount}\n\n*Click to open Security Dashboard*`
		);
		this.statusBarItem.show();
	}

	dispose(): void {
		this.statusBarItem.dispose();
	}
}
