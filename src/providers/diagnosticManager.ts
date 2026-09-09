import * as vscode from 'vscode';
import { SecurityFinding } from '../models/finding';

export class DiagnosticManager {
	constructor(private readonly diagnosticCollection: vscode.DiagnosticCollection) {}

	updateDiagnostics(findings: SecurityFinding[], scannedFiles: vscode.Uri[]): void {
		this.diagnosticCollection.clear();

		// Group findings by file URI
		const findingsByFile = new Map<string, SecurityFinding[]>();
		for (const finding of findings) {
			const uriStr = finding.file.toString();
			if (!findingsByFile.has(uriStr)) {
				findingsByFile.set(uriStr, []);
			}
			findingsByFile.get(uriStr)!.push(finding);
		}

		const filesToUpdate = new Map<string, vscode.Uri>();
		for (const file of scannedFiles) {
			filesToUpdate.set(file.toString(), file);
		}
		for (const finding of findings) {
			filesToUpdate.set(finding.file.toString(), finding.file);
		}

		for (const file of filesToUpdate.values()) {
			const fileFindings = findingsByFile.get(file.toString()) || [];
			const diagnostics: vscode.Diagnostic[] = fileFindings.map(finding => {
				const startLine = Math.max(0, finding.line - 1);
				const startCol = Math.max(0, (finding.column || 1) - 1);
				const endLine = finding.endLine ? Math.max(0, finding.endLine - 1) : startLine;
				const endCol = finding.endColumn ? Math.max(0, finding.endColumn - 1) : startCol + 20;

				const range = new vscode.Range(startLine, startCol, endLine, endCol);
				const severity = this.toVsCodeSeverity(finding.severity);

				const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
				diagnostic.source = 'Spring Security Inspector';
				diagnostic.code = finding.cweId ? `${finding.ruleId} (${finding.cweId})` : finding.ruleId;
				return diagnostic;
			});

			this.diagnosticCollection.set(file, diagnostics);
		}
	}

	clear(): void {
		this.diagnosticCollection.clear();
	}

	private toVsCodeSeverity(severity: string): vscode.DiagnosticSeverity {
		switch (severity) {
			case 'error':
				return vscode.DiagnosticSeverity.Error;
			case 'warning':
				return vscode.DiagnosticSeverity.Warning;
			case 'info':
			default:
				return vscode.DiagnosticSeverity.Information;
		}
	}
}
