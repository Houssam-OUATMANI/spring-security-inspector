import * as vscode from 'vscode';
import { SecuritySummary, createEmptySummary } from '../models/summary';
import { SecurityRoute } from '../models/route';
import { SecurityFinding } from '../models/finding';
import { SecurityComponent } from '../models/component';
import { ControllerEndpoint } from '../models/controller';

export type TreeItemData =
	| { kind: 'root'; label: string; count?: number; category: 'routes' | 'endpoints' | 'findings' | 'auth' | 'filters' | 'methodSecurity' }
	| { kind: 'route'; route: SecurityRoute }
	| { kind: 'endpoint'; endpoint: ControllerEndpoint }
	| { kind: 'finding'; finding: SecurityFinding }
	| { kind: 'component'; component: SecurityComponent }
	| { kind: 'empty'; message: string };

export class SecurityTreeItem extends vscode.TreeItem {
	constructor(
		public readonly data: TreeItemData,
		label: string,
		collapsibleState: vscode.TreeItemCollapsibleState,
		description?: string,
		tooltip?: string | vscode.MarkdownString
	) {
		super(label, collapsibleState);
		this.description = description;
		this.tooltip = tooltip;
	}
}

export class SecurityTreeProvider implements vscode.TreeDataProvider<SecurityTreeItem> {
	private readonly changeEmitter = new vscode.EventEmitter<SecurityTreeItem | undefined | void>();
	readonly onDidChangeTreeData = this.changeEmitter.event;
	private summary: SecuritySummary = createEmptySummary();

	setSummary(summary: SecuritySummary): void {
		this.summary = summary;
		this.changeEmitter.fire();
	}

	refresh(): void {
		this.changeEmitter.fire();
	}

	dispose(): void {
		this.changeEmitter.dispose();
	}

	getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: SecurityTreeItem): SecurityTreeItem[] {
		if (!element) {
			return this.getRootItems();
		}

		if (element.data.kind === 'root') {
			switch (element.data.category) {
				case 'routes':
					return this.getRouteItems();
				case 'endpoints':
					return this.getEndpointItems();
				case 'findings':
					return this.getFindingItems();
				case 'auth':
					return this.getAuthComponentItems();
				case 'filters':
					return this.getFilterComponentItems();
				case 'methodSecurity':
					return this.getMethodSecurityItems();
			}
		}

		return [];
	}

	private getRootItems(): SecurityTreeItem[] {
		if (!this.summary.projectDetected) {
			const item = new SecurityTreeItem(
				{ kind: 'empty', message: 'No Spring Security project detected' },
				'Open a Spring project to begin analysis',
				vscode.TreeItemCollapsibleState.None,
				undefined,
				new vscode.MarkdownString('**Spring Security Inspector**\n\nNo Spring Security project detected in the current workspace.\n\nOpen a project containing `pom.xml` or `build.gradle` with a Spring Security dependency.')
			);
			item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('notificationsInfoIcon.foreground'));
			return [item];
		}

		const items: SecurityTreeItem[] = [];

		// 1. Routes & Authorization
		const errCount = this.summary.findings.filter(f => f.severity === 'error').length;
		const warnCount = this.summary.findings.filter(f => f.severity === 'warning').length;
		const publicCount = this.summary.routes.filter(r => r.accessLevel === 'permitAll').length;
		const restrictedCount = this.summary.routes.filter(r => r.accessLevel !== 'permitAll' && r.accessLevel !== 'denyAll').length;

		const routeItem = new SecurityTreeItem(
			{ kind: 'root', label: 'Security Rules', count: this.summary.routes.length, category: 'routes' },
			'Security Rules',
			this.summary.routes.length > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed,
			`${this.summary.routes.length} matcher${this.summary.routes.length !== 1 ? 's' : ''}`,
			new vscode.MarkdownString(
				`**Security Matchers** — ${this.summary.routes.length} configured rules\n\n` +
				`🔓 ${publicCount} public  •  🔒 ${restrictedCount} restricted`
			)
		);
		routeItem.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.blue'));
		items.push(routeItem);

		// 2. Controller Endpoints
		if (this.summary.endpoints.length > 0) {
			const endpointItem = new SecurityTreeItem(
				{ kind: 'root', label: 'Controller Endpoints', count: this.summary.endpoints.length, category: 'endpoints' },
				'Controller Endpoints',
				vscode.TreeItemCollapsibleState.Collapsed,
				`${this.summary.endpoints.length} endpoint${this.summary.endpoints.length !== 1 ? 's' : ''}`,
				new vscode.MarkdownString(`**@RestController Endpoints**\n\nDetected ${this.summary.endpoints.length} mapped endpoints from controller annotations.`)
			);
			endpointItem.iconPath = new vscode.ThemeIcon('server-process');
			items.push(endpointItem);
		}

		// 3. Security Findings
		const findingCount = this.summary.findings.length;
		let findingDesc: string;
		if (findingCount === 0) {
			findingDesc = 'All clear ✓';
		} else {
			const parts: string[] = [];
			if (errCount > 0) {parts.push(`${errCount} error${errCount > 1 ? 's' : ''}`);}
			if (warnCount > 0) {parts.push(`${warnCount} warning${warnCount > 1 ? 's' : ''}`);}
			const infoCount = findingCount - errCount - warnCount;
			if (infoCount > 0) {parts.push(`${infoCount} info`);}
			findingDesc = parts.join(', ');
		}

		const findingItem = new SecurityTreeItem(
			{ kind: 'root', label: 'Security Findings', count: findingCount, category: 'findings' },
			'Security Findings',
			findingCount > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed,
			findingDesc,
			new vscode.MarkdownString(`**Security Findings** — ${findingCount} issue${findingCount !== 1 ? 's' : ''} detected\n\n⛔ ${errCount} errors  •  ⚠️ ${warnCount} warnings`)
		);
		if (findingCount > 0) {
			findingItem.iconPath = new vscode.ThemeIcon(
				errCount > 0 ? 'error' : 'warning',
				new vscode.ThemeColor(errCount > 0 ? 'notificationsErrorIcon.foreground' : 'notificationsWarningIcon.foreground')
			);
		} else {
			findingItem.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
		}
		items.push(findingItem);

		// 4. Authentication beans
		const authComponents = this.summary.components.filter(
			c => c.type === 'authentication' || c.type === 'passwordEncoder'
		);
		const authItem = new SecurityTreeItem(
			{ kind: 'root', label: 'Authentication', count: authComponents.length, category: 'auth' },
			'Authentication',
			vscode.TreeItemCollapsibleState.Collapsed,
			authComponents.length > 0 ? `${authComponents.length} bean${authComponents.length !== 1 ? 's' : ''}` : 'Spring defaults',
			new vscode.MarkdownString(`**Authentication Beans**\n\nUserDetailsService, PasswordEncoder and related authentication components.`)
		);
		authItem.iconPath = new vscode.ThemeIcon('key');
		items.push(authItem);

		// 5. Security Filter Chain
		const filterComponents = this.summary.components.filter(c => c.type === 'filter');
		const filterItem = new SecurityTreeItem(
			{ kind: 'root', label: 'Filter Chain', count: filterComponents.length, category: 'filters' },
			'Filter Chain',
			vscode.TreeItemCollapsibleState.Collapsed,
			filterComponents.length > 0 ? `${filterComponents.length} custom filter${filterComponents.length !== 1 ? 's' : ''}` : 'Default chain',
			new vscode.MarkdownString(`**SecurityFilterChain**\n\nCustom servlet filters added to the Spring Security filter chain.`)
		);
		filterItem.iconPath = new vscode.ThemeIcon('layers');
		items.push(filterItem);

		// 6. Method Security
		const methodComponents = this.summary.components.filter(c => c.type === 'methodSecurity');
		if (methodComponents.length > 0) {
			const methodItem = new SecurityTreeItem(
				{ kind: 'root', label: 'Method Security', count: methodComponents.length, category: 'methodSecurity' },
				'Method Security',
				vscode.TreeItemCollapsibleState.Collapsed,
				`${methodComponents.length} secured method${methodComponents.length !== 1 ? 's' : ''}`,
				new vscode.MarkdownString(`**Method-Level Security**\n\n@PreAuthorize, @PostAuthorize, @Secured annotations detected.`)
			);
			methodItem.iconPath = new vscode.ThemeIcon('symbol-method');
			items.push(methodItem);
		}

		return items;
	}

	private getRouteItems(): SecurityTreeItem[] {
		if (this.summary.routes.length === 0) {
			const item = new SecurityTreeItem(
				{ kind: 'empty', message: 'No explicit request matchers found' },
				'No explicit matchers detected',
				vscode.TreeItemCollapsibleState.None,
				undefined,
				'Add .requestMatchers(...) to your HttpSecurity configuration.'
			);
			item.iconPath = new vscode.ThemeIcon('info');
			return [item];
		}

		return this.summary.routes.map(route => {
			const methodPart = route.method !== 'ANY' ? `[${route.method}] ` : '';
			const label = `${methodPart}${route.pattern}`;
			let description = this.describeAccessLevel(route.accessLevel);
			if (route.requiredRolesOrAuthorities && route.requiredRolesOrAuthorities.length > 0) {
				description += `: ${route.requiredRolesOrAuthorities.join(', ')}`;
			}

			const md = new vscode.MarkdownString();
			md.isTrusted = true;
			md.appendMarkdown(`**Pattern:** \`${route.pattern}\`\n\n`);
			md.appendMarkdown(`**Method:** \`${route.method}\`\n\n`);
			md.appendMarkdown(`**Access:** \`${route.accessLevel}\`\n\n`);
			if (route.requiredRolesOrAuthorities && route.requiredRolesOrAuthorities.length > 0) {
				md.appendMarkdown(`**Required:** ${route.requiredRolesOrAuthorities.map(r => `\`${r}\``).join(', ')}\n\n`);
			}
			md.appendMarkdown(`*${route.file.fsPath}:${route.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'route', route },
				label,
				vscode.TreeItemCollapsibleState.None,
				description,
				md
			);

			item.iconPath = this.getRouteIcon(route.accessLevel);

			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [route.file, route.line, route.column],
			};

			return item;
		});
	}

	private getEndpointItems(): SecurityTreeItem[] {
		return this.summary.endpoints.map(ep => {
			const label = `[${ep.httpMethod}] ${ep.fullPath}`;
			const desc = `${ep.controllerClass}::${ep.methodName}()`;

			const md = new vscode.MarkdownString();
			md.appendMarkdown(`**\`${ep.httpMethod} ${ep.fullPath}\`**\n\n`);
			md.appendMarkdown(`Controller: \`${ep.controllerClass}\`\n\n`);
			md.appendMarkdown(`Method: \`${ep.methodName}()\`\n\n`);
			md.appendMarkdown(`*${ep.file.fsPath}:${ep.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'endpoint', endpoint: ep },
				label,
				vscode.TreeItemCollapsibleState.None,
				desc,
				md
			);
			item.iconPath = new vscode.ThemeIcon('symbol-method');
			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [ep.file, ep.line, ep.column],
			};
			return item;
		});
	}

	private getFindingItems(): SecurityTreeItem[] {
		if (this.summary.findings.length === 0) {
			const item = new SecurityTreeItem(
				{ kind: 'empty', message: 'No vulnerabilities detected' },
				'All security checks passed!',
				vscode.TreeItemCollapsibleState.None,
				undefined,
				'No issues detected. Your Spring Security configuration looks good.'
			);
			item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
			return [item];
		}

		// Sort: errors first, then warnings, then info
		const sorted = [...this.summary.findings].sort((a, b) => {
			const order = { error: 0, warning: 1, info: 2 };
			return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
		});

		return sorted.map(finding => {
			const cweLabel = finding.cweId ? `[${finding.cweId}] ` : '';
			const shortFile = finding.file.fsPath.split(/[\\/]/).slice(-2).join('/');

			const md = new vscode.MarkdownString();
			md.isTrusted = true;
			md.appendMarkdown(`**${finding.ruleId}**`);
			if (finding.cweId) {md.appendMarkdown(` — [${finding.cweId}](https://cwe.mitre.org/data/definitions/${finding.cweId.replace('CWE-', '')}.html)`);}
			md.appendMarkdown(`\n\n${finding.message}\n\n`);
			if (finding.recommendation) {
				md.appendMarkdown(`> 💡 ${finding.recommendation}\n\n`);
			}
			md.appendMarkdown(`*${shortFile}:${finding.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'finding', finding },
				finding.message,
				vscode.TreeItemCollapsibleState.None,
				`${cweLabel}${shortFile}:${finding.line}`,
				md
			);

			if (finding.severity === 'error') {
				item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('notificationsErrorIcon.foreground'));
			} else if (finding.severity === 'warning') {
				item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('notificationsWarningIcon.foreground'));
			} else {
				item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('notificationsInfoIcon.foreground'));
			}

			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [finding.file, finding.line, finding.column || 1],
			};

			return item;
		});
	}

	private getAuthComponentItems(): SecurityTreeItem[] {
		const authComponents = this.summary.components.filter(
			c => c.type === 'authentication' || c.type === 'passwordEncoder'
		);

		if (authComponents.length === 0) {
			const item = new SecurityTreeItem(
				{ kind: 'empty', message: 'No custom authentication beans detected' },
				'Spring Boot defaults active',
				vscode.TreeItemCollapsibleState.None,
				undefined,
				'No custom UserDetailsService or PasswordEncoder beans found. Spring Boot auto-configuration is in use.'
			);
			item.iconPath = new vscode.ThemeIcon('info');
			return [item];
		}

		return authComponents.map(comp => {
			const md = new vscode.MarkdownString();
			md.appendMarkdown(`**${comp.name}**\n\n`);
			md.appendMarkdown(`Type: \`${comp.type}\`\n\n`);
			if (comp.details) {md.appendMarkdown(`Details: ${comp.details}\n\n`);}
			md.appendMarkdown(`*${comp.file.fsPath}:${comp.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'component', component: comp },
				comp.name,
				vscode.TreeItemCollapsibleState.None,
				comp.details,
				md
			);
			item.iconPath = new vscode.ThemeIcon(
				comp.type === 'passwordEncoder' ? 'lock' : 'person',
				new vscode.ThemeColor('charts.green')
			);
			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [comp.file, comp.line, comp.column || 1],
			};
			return item;
		});
	}

	private getFilterComponentItems(): SecurityTreeItem[] {
		const filterComponents = this.summary.components.filter(c => c.type === 'filter');

		if (filterComponents.length === 0) {
			const item = new SecurityTreeItem(
				{ kind: 'empty', message: 'Standard Spring Security filters in use' },
				'Default SecurityFilterChain active',
				vscode.TreeItemCollapsibleState.None,
				undefined,
				'No custom servlet filters detected. Spring Security uses its standard built-in filter chain.'
			);
			item.iconPath = new vscode.ThemeIcon('info');
			return [item];
		}

		return filterComponents.map(comp => {
			const md = new vscode.MarkdownString();
			md.appendMarkdown(`**${comp.name}**\n\n`);
			if (comp.details) {md.appendMarkdown(`${comp.details}\n\n`);}
			md.appendMarkdown(`*${comp.file.fsPath}:${comp.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'component', component: comp },
				comp.name,
				vscode.TreeItemCollapsibleState.None,
				comp.details,
				md
			);
			item.iconPath = new vscode.ThemeIcon('filter');
			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [comp.file, comp.line, comp.column || 1],
			};
			return item;
		});
	}

	private getMethodSecurityItems(): SecurityTreeItem[] {
		const methodComponents = this.summary.components.filter(c => c.type === 'methodSecurity');

		return methodComponents.map(comp => {
			const md = new vscode.MarkdownString();
			md.appendMarkdown(`**${comp.name}**\n\n`);
			if (comp.details) {md.appendMarkdown(`${comp.details}\n\n`);}
			md.appendMarkdown(`*${comp.file.fsPath}:${comp.line}*`);

			const item = new SecurityTreeItem(
				{ kind: 'component', component: comp },
				comp.name,
				vscode.TreeItemCollapsibleState.None,
				comp.details,
				md
			);
			item.iconPath = new vscode.ThemeIcon('symbol-method', new vscode.ThemeColor('charts.purple'));
			item.command = {
				command: 'spring-security-inspector.openFile',
				title: 'Open File',
				arguments: [comp.file, comp.line, comp.column || 1],
			};
			return item;
		});
	}

	private describeAccessLevel(accessLevel: string): string {
		const map: Record<string, string> = {
			permitAll: '🔓 Public',
			anonymous: '🔓 Anonymous',
			denyAll: '⛔ Deny All',
			authenticated: '🔑 Auth Required',
			fullyAuthenticated: '🔐 Fully Auth',
			rememberMe: '🔑 Remember-Me',
			hasRole: '🛡 Role Required',
			hasAnyRole: '🛡 Any Role',
			hasAuthority: '🔏 Authority',
			hasAnyAuthority: '🔏 Any Authority',
		};
		return map[accessLevel] ?? `⚡ ${accessLevel}`;
	}

	private getRouteIcon(accessLevel: string): vscode.ThemeIcon {
		switch (accessLevel) {
			case 'permitAll':
			case 'anonymous':
				return new vscode.ThemeIcon('unlock', new vscode.ThemeColor('charts.green'));
			case 'denyAll':
				return new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('charts.red'));
			case 'authenticated':
			case 'fullyAuthenticated':
			case 'rememberMe':
				return new vscode.ThemeIcon('lock', new vscode.ThemeColor('charts.yellow'));
			case 'hasRole':
			case 'hasAnyRole':
				return new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.blue'));
			case 'hasAuthority':
			case 'hasAnyAuthority':
				return new vscode.ThemeIcon('key', new vscode.ThemeColor('charts.purple'));
			default:
				return new vscode.ThemeIcon('question', new vscode.ThemeColor('charts.orange'));
		}
	}
}
