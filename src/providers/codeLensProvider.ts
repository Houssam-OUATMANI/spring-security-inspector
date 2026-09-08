import * as vscode from 'vscode';
import { SecuritySummary } from '../models/summary';

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
	private summary: SecuritySummary | null = null;
	private readonly onDidChangeCodeLensesEmitter = new vscode.EventEmitter<void>();
	public readonly onDidChangeCodeLenses = this.onDidChangeCodeLensesEmitter.event;

	setSummary(summary: SecuritySummary): void {
		this.summary = summary;
		this.onDidChangeCodeLensesEmitter.fire();
	}

	provideCodeLenses(
		document: vscode.TextDocument,
		_token: vscode.CancellationToken
	): vscode.ProviderResult<vscode.CodeLens[]> {
		if (!this.summary || !this.summary.projectDetected) {
			return [];
		}

		const codeLenses: vscode.CodeLens[] = [];
		const text = document.getText();
		const lines = text.split('\n');

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			// Match SecurityFilterChain bean definitions or class-level security annotations
			if (line.includes('SecurityFilterChain') && line.includes('@Bean')) {
				const range = new vscode.Range(i, 0, i, line.length);
				const fileRoutes = this.summary.routes.filter(r => r.file.fsPath === document.uri.fsPath);
				const fileFindings = this.summary.findings.filter(f => f.file.fsPath === document.uri.fsPath);

				const title = `🛡️ Spring Security: ${fileRoutes.length} routes | ${fileFindings.length} alert${fileFindings.length === 1 ? '' : 's'}`;

				const codeLens = new vscode.CodeLens(range, {
					title,
					command: 'spring-security-inspector.refresh',
					tooltip: 'Click to refresh and view Spring Security Analysis in the Activity Bar',
				});
				codeLenses.push(codeLens);
			}
		}

		return codeLenses;
	}
}
