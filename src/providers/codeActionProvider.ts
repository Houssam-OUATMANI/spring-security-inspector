import * as vscode from 'vscode';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
	public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

	provideCodeActions(
		document: vscode.TextDocument,
		range: vscode.Range | vscode.Selection,
		context: vscode.CodeActionContext,
		_token: vscode.CancellationToken
	): vscode.CodeAction[] {
		const actions: vscode.CodeAction[] = [];

		for (const diagnostic of context.diagnostics) {
			if (diagnostic.source !== 'Spring Security Inspector') {
				continue;
			}

			const line = document.lineAt(diagnostic.range.start.line);
			const lineText = line.text;

			// Quick fix for anyRequest().permitAll()
			if (lineText.includes('.anyRequest().permitAll()')) {
				const fix = new vscode.CodeAction(
					'Change anyRequest().permitAll() to anyRequest().authenticated()',
					vscode.CodeActionKind.QuickFix
				);
				fix.diagnostics = [diagnostic];
				fix.isPreferred = true;
				fix.edit = new vscode.WorkspaceEdit();
				const targetIndex = lineText.indexOf('.anyRequest().permitAll()');
				const replaceRange = new vscode.Range(
					line.lineNumber,
					targetIndex,
					line.lineNumber,
					targetIndex + '.anyRequest().permitAll()'.length
				);
				fix.edit.replace(document.uri, replaceRange, '.anyRequest().authenticated()');
				actions.push(fix);
			}

			// Quick fix for NoOpPasswordEncoder
			if (lineText.includes('NoOpPasswordEncoder.getInstance()')) {
				const fix = new vscode.CodeAction(
					'Replace with new BCryptPasswordEncoder()',
					vscode.CodeActionKind.QuickFix
				);
				fix.diagnostics = [diagnostic];
				fix.isPreferred = true;
				fix.edit = new vscode.WorkspaceEdit();
				const targetIndex = lineText.indexOf('NoOpPasswordEncoder.getInstance()');
				const replaceRange = new vscode.Range(
					line.lineNumber,
					targetIndex,
					line.lineNumber,
					targetIndex + 'NoOpPasswordEncoder.getInstance()'.length
				);
				fix.edit.replace(document.uri, replaceRange, 'new BCryptPasswordEncoder()');
				actions.push(fix);
			}

			// Quick fix for CSRF disabled
			if (lineText.includes('AbstractHttpConfigurer::disable')) {
				const fix = new vscode.CodeAction(
					'Enable CSRF with Customizer.withDefaults()',
					vscode.CodeActionKind.QuickFix
				);
				fix.diagnostics = [diagnostic];
				fix.edit = new vscode.WorkspaceEdit();
				const targetIndex = lineText.indexOf('AbstractHttpConfigurer::disable');
				const replaceRange = new vscode.Range(
					line.lineNumber,
					targetIndex,
					line.lineNumber,
					targetIndex + 'AbstractHttpConfigurer::disable'.length
				);
				fix.edit.replace(document.uri, replaceRange, 'Customizer.withDefaults()');
				actions.push(fix);
			}
		}

		return actions;
	}
}
