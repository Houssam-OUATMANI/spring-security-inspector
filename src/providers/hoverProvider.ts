import * as vscode from 'vscode';
import { SecuritySummary } from '../models/summary';

export class SecurityHoverProvider implements vscode.HoverProvider {
	private summary: SecuritySummary | null = null;

	setSummary(summary: SecuritySummary): void {
		this.summary = summary;
	}

	provideHover(
		document: vscode.TextDocument,
		position: vscode.Position,
		_token: vscode.CancellationToken
	): vscode.ProviderResult<vscode.Hover> {
		const range = document.getWordRangeAtPosition(position, /[a-zA-Z0-9_.@"'*]+/);
		if (!range) {
			return null;
		}

		const lineText = document.lineAt(position.line).text;

		if (lineText.includes('requestMatchers') || lineText.includes('antMatchers')) {
			const md = new vscode.MarkdownString();
			md.appendMarkdown(`### 🛡️ Spring Security Route Matcher\n\n`);
			md.appendMarkdown(`Defines access rules for HTTP endpoints. In Spring Security, **rules are evaluated in top-down order** (first match wins).\n\n`);

			// Find matching route in summary if available
			if (this.summary) {
				const matchingRoute = this.summary.routes.find(
					r => r.file.fsPath === document.uri.fsPath && r.line === position.line + 1
				);
				if (matchingRoute) {
					md.appendMarkdown(`- **Pattern:** \`${matchingRoute.pattern}\`\n`);
					md.appendMarkdown(`- **Method:** \`${matchingRoute.method}\`\n`);
					md.appendMarkdown(`- **Access Level:** \`${matchingRoute.accessLevel}\`\n`);
					if (matchingRoute.requiredRolesOrAuthorities) {
						md.appendMarkdown(`- **Required:** \`${matchingRoute.requiredRolesOrAuthorities.join(', ')}\`\n`);
					}
				}
			}

			md.appendMarkdown(`\n> **Tip:** Always ensure specific rules precede generic rules like \`/**\`.`);
			return new vscode.Hover(md, range);
		}

		if (lineText.includes('PreAuthorize')) {
			const md = new vscode.MarkdownString();
			md.appendMarkdown(`### 🔒 Method Security (@PreAuthorize)\n\n`);
			md.appendMarkdown(`Secures this method via Spring Expression Language (SpEL) before execution.\n\n`);
			md.appendMarkdown(`> Requires \`@EnableMethodSecurity\` on a configuration class.`);
			return new vscode.Hover(md, range);
		}

		return null;
	}
}
