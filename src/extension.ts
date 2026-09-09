import * as vscode from 'vscode';
import { SecurityTreeProvider } from './providers/securityTreeProvider';
import { DiagnosticManager } from './providers/diagnosticManager';
import { SecurityCodeLensProvider } from './providers/codeLensProvider';
import { SecurityHoverProvider } from './providers/hoverProvider';
import { SecurityCodeActionProvider } from './providers/codeActionProvider';
import { SecurityStatusBarItem } from './providers/statusBarItem';
import { SecurityDashboardPanel } from './providers/dashboardWebview';
import { AnalysisCache } from './services/analysisCache';
import { debounce } from './services/debounce';
import { detectProject } from './analyzer/projectDetector';
import { analyzeJavaFile } from './analyzer';
import { createEmptySummary, SecuritySummary } from './models/summary';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
	const treeProvider = new SecurityTreeProvider();
	const diagnosticCollection = vscode.languages.createDiagnosticCollection('spring-security-inspector');
	const diagnosticManager = new DiagnosticManager(diagnosticCollection);
	const codeLensProvider = new SecurityCodeLensProvider();
	const hoverProvider = new SecurityHoverProvider();
	const codeActionProvider = new SecurityCodeActionProvider();
	const statusBarItem = new SecurityStatusBarItem();
	const analysisCache = new AnalysisCache();

	let latestSummary: SecuritySummary = createEmptySummary();

	const treeView = vscode.window.createTreeView('spring-security-overview', {
		treeDataProvider: treeProvider,
		showCollapseAll: true,
	});

	// Register Open File Command (used by clickable tree items & dashboard)
	const openFileCommand = vscode.commands.registerCommand(
		'spring-security-inspector.openFile',
		async (fileUri: vscode.Uri, line: number, column?: number) => {
			try {
				const doc = await vscode.workspace.openTextDocument(fileUri);
				const editor = await vscode.window.showTextDocument(doc);
				const zeroLine = Math.max(0, line - 1);
				const zeroCol = Math.max(0, (column || 1) - 1);
				const position = new vscode.Position(zeroLine, zeroCol);
				editor.selection = new vscode.Selection(position, position);
				editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
			} catch (err) {
				void vscode.window.showErrorMessage(`Unable to open file: ${fileUri.fsPath}`);
			}
		}
	);

	// Register Open Dashboard Command
	const openDashboardCommand = vscode.commands.registerCommand(
		'spring-security-inspector.openDashboard',
		() => {
			SecurityDashboardPanel.render(context.extensionUri, latestSummary);
		}
	);

	const exportSarifCommand = vscode.commands.registerCommand(
		'spring-security-inspector.exportSarif',
		async () => {
			if (!SecurityDashboardPanel.currentPanel) {
				SecurityDashboardPanel.render(context.extensionUri, latestSummary);
			}
			await SecurityDashboardPanel.currentPanel?.exportSarif();
		}
	);

	const runFullScan = async (): Promise<void> => {
		const config = vscode.workspace.getConfiguration('springSecurityInspector');
		const isDiagnosticsEnabled = config.get<boolean>('enableDiagnostics', true);

		const projectInfo = await detectProject();
		await vscode.commands.executeCommand(
			'setContext',
			'springSecurityInspector.projectDetected',
			projectInfo.projectDetected
		);

		if (!projectInfo.projectDetected) {
			latestSummary = createEmptySummary();
			treeProvider.setSummary(latestSummary);
			codeLensProvider.setSummary(latestSummary);
			hoverProvider.setSummary(latestSummary);
			statusBarItem.update(latestSummary);
			SecurityDashboardPanel.currentPanel?.updateSummary(latestSummary);
			diagnosticManager.clear();
			return;
		}

		// Find Java files
		const ignorePatterns = config.get<string[]>('ignorePatterns', ['**/test/**']);
		const builtInExcluded = ['target', 'build', '.gradle', 'node_modules'];
		const excludePatterns = [
			...builtInExcluded.map(pattern => `**/${pattern}/**`),
			...ignorePatterns,
		];
		const javaFiles = await vscode.workspace.findFiles('**/*.java', `{${excludePatterns.join(',')}}`);

		analysisCache.clear();

		// Read and analyze files
		for (const file of javaFiles) {
			try {
				const fileBytes = await vscode.workspace.fs.readFile(file);
				const text = Buffer.from(fileBytes).toString('utf8');
				const result = analyzeJavaFile(text, file);
				analysisCache.setFileAnalysis(file, result);
			} catch {
				// Ignore file read error
			}
		}

		latestSummary = await analysisCache.buildSummary(true, projectInfo.springSecurityVersion);
		treeProvider.setSummary(latestSummary);
		codeLensProvider.setSummary(latestSummary);
		hoverProvider.setSummary(latestSummary);
		statusBarItem.update(latestSummary);
		SecurityDashboardPanel.currentPanel?.updateSummary(latestSummary);

		if (isDiagnosticsEnabled) {
			diagnosticManager.updateDiagnostics(latestSummary.findings, javaFiles);
		} else {
			diagnosticManager.clear();
		}
	};

	const debouncedScan = debounce(() => {
		void runFullScan();
	}, 350);

	const refreshCommand = vscode.commands.registerCommand('spring-security-inspector.refresh', async () => {
		await runFullScan();
		void vscode.window.showInformationMessage('Spring Security analysis refreshed.');
	});

	// Register language providers for Java
	const javaSelector: vscode.DocumentSelector = { scheme: 'file', language: 'java' };
	const codeLensRegistration = vscode.languages.registerCodeLensProvider(javaSelector, codeLensProvider);
	const hoverRegistration = vscode.languages.registerHoverProvider(javaSelector, hoverProvider);
	const codeActionRegistration = vscode.languages.registerCodeActionsProvider(
		javaSelector,
		codeActionProvider,
		{ providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds }
	);

	// Watch file changes
	const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(doc => {
		const config = vscode.workspace.getConfiguration('springSecurityInspector');
		if (!config.get<boolean>('scanOnSave', true)) {
			return;
		}

		if (
			doc.languageId === 'java' ||
			doc.fileName.endsWith('pom.xml') ||
			doc.fileName.endsWith('.gradle') ||
			doc.fileName.endsWith('.gradle.kts') ||
			doc.fileName.includes('application.')
		) {
			debouncedScan();
		}
	});

	const onDeleteDisposable = vscode.workspace.onDidDeleteFiles(event => {
		for (const file of event.files) {
			analysisCache.removeFile(file);
		}
		debouncedScan();
	});

	context.subscriptions.push(
		diagnosticCollection,
		treeView,
		treeProvider,
		statusBarItem,
		openFileCommand,
		openDashboardCommand,
		exportSarifCommand,
		refreshCommand,
		codeLensRegistration,
		hoverRegistration,
		codeActionRegistration,
		onSaveDisposable,
		onDeleteDisposable
	);

	// Initial scan
	await runFullScan();
}

export function deactivate(): void {}
