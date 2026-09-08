import * as vscode from 'vscode';
import { SecuritySummary, SpringSecurityVersion } from '../models/summary';
import { FileAnalysisResult, analyzeCrossFileRules } from '../analyzer';
import { SecurityRoute } from '../models/route';
import { SecurityFinding } from '../models/finding';
import { SecurityComponent } from '../models/component';
import { ControllerEndpoint } from '../models/controller';

export class AnalysisCache {
	private readonly cache = new Map<string, FileAnalysisResult>();

	setFileAnalysis(file: vscode.Uri, result: FileAnalysisResult): void {
		this.cache.set(file.toString(), result);
	}

	removeFile(file: vscode.Uri): void {
		this.cache.delete(file.toString());
	}

	clear(): void {
		this.cache.clear();
	}

	hasFile(file: vscode.Uri): boolean {
		return this.cache.has(file.toString());
	}

	async buildSummary(projectDetected: boolean, springSecurityVersion: SpringSecurityVersion): Promise<SecuritySummary> {
		const allRoutes: SecurityRoute[] = [];
		const allEndpoints: ControllerEndpoint[] = [];
		const allFindings: SecurityFinding[] = [];
		const allComponents: SecurityComponent[] = [];
		const files: vscode.Uri[] = [];

		for (const [uriStr, result] of this.cache.entries()) {
			allRoutes.push(...result.routes);
			allEndpoints.push(...result.endpoints);
			allFindings.push(...result.findings);
			allComponents.push(...result.components);
			files.push(vscode.Uri.parse(uriStr));
		}

		// Run cross-file rules (route shadowing, controller reconciliation, and properties audit)
		const { crossFindings } = await analyzeCrossFileRules(allRoutes, allEndpoints);
		allFindings.push(...crossFindings);

		return {
			projectDetected,
			springSecurityVersion,
			routes: allRoutes,
			endpoints: allEndpoints,
			findings: allFindings,
			components: allComponents,
			files,
			scannedAt: new Date(),
		};
	}
}
