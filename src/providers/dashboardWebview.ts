import * as vscode from 'vscode';
import { SecuritySummary } from '../models/summary';
import { HttpMethod } from '../models/route';

export class SecurityDashboardPanel {
	public static currentPanel: SecurityDashboardPanel | undefined;
	private readonly panel: vscode.WebviewPanel;
	private summary: SecuritySummary;
	private disposables: vscode.Disposable[] = [];

	private constructor(panel: vscode.WebviewPanel, summary: SecuritySummary) {
		this.panel = panel;
		this.summary = summary;

		this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
		this.panel.webview.onDidReceiveMessage(
			async message => {
				switch (message.command) {
					case 'exportMarkdown':
						await this.exportMarkdownReport();
						break;
					case 'exportJson':
						await this.exportJsonReport();
						break;
					case 'openFile':
						if (message.file && message.line) {
							const uri = vscode.Uri.parse(message.file);
							await vscode.commands.executeCommand('spring-security-inspector.openFile', uri, message.line, 1);
						}
						break;
				}
			},
			null,
			this.disposables
		);

		this.render();
	}

	public static render(extensionUri: vscode.Uri, summary: SecuritySummary): void {
		const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;

		if (SecurityDashboardPanel.currentPanel) {
			SecurityDashboardPanel.currentPanel.summary = summary;
			SecurityDashboardPanel.currentPanel.panel.reveal(column);
			SecurityDashboardPanel.currentPanel.render();
			return;
		}

		const panel = vscode.window.createWebviewPanel(
			'springSecurityDashboard',
			'Spring Security Dashboard',
			column || vscode.ViewColumn.One,
			{
				enableScripts: true,
				retainContextWhenHidden: true,
			}
		);

		SecurityDashboardPanel.currentPanel = new SecurityDashboardPanel(panel, summary);
	}

	public updateSummary(summary: SecuritySummary): void {
		this.summary = summary;
		this.render();
	}

	private render(): void {
		this.panel.webview.html = this.getHtmlContent();
	}

	private async exportMarkdownReport(): Promise<void> {
		const md = generateMarkdownReport(this.summary);
		const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
		await vscode.window.showTextDocument(doc, { preview: false });
		void vscode.window.showInformationMessage('Security report generated as Markdown.');
	}

	private async exportJsonReport(): Promise<void> {
		const json = JSON.stringify(
			{
				generatedAt: new Date().toISOString(),
				springSecurityVersion: this.summary.springSecurityVersion,
				stats: {
					routesCount: this.summary.routes.length,
					endpointsCount: this.summary.endpoints.length,
					findingsCount: this.summary.findings.length,
				},
				routes: this.summary.routes,
				endpoints: this.summary.endpoints,
				findings: this.summary.findings,
			},
			null,
			2
		);

		const doc = await vscode.workspace.openTextDocument({ content: json, language: 'json' });
		await vscode.window.showTextDocument(doc, { preview: false });
		void vscode.window.showInformationMessage('Security audit data exported as JSON.');
	}

	private getHtmlContent(): string {
		const summary = this.summary;
		const routesJson = JSON.stringify(summary.routes);
		const endpointsJson = JSON.stringify(summary.endpoints);
		const findingsJson = JSON.stringify(summary.findings);

		const errorsCount = summary.findings.filter(f => f.severity === 'error').length;
		const warningsCount = summary.findings.filter(f => f.severity === 'warning').length;
		const infoCount = summary.findings.filter(f => f.severity === 'info').length;
		const versionLabel =
			summary.springSecurityVersion === 'spring-security-6'
				? 'Spring Security 6'
				: summary.springSecurityVersion === 'spring-security-5'
				? 'Spring Security 5'
				: 'Unknown';

		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Spring Security Dashboard</title>
	<style>
		*, *::before, *::after { box-sizing: border-box; }
		:root {
			--bg: var(--vscode-editor-background);
			--fg: var(--vscode-editor-foreground);
			--card-bg: var(--vscode-sideBar-background, #1e1e1e);
			--card-bg2: var(--vscode-editorGroupHeader-tabsBackground, #252526);
			--border: var(--vscode-panel-border, #3c3c3c);
			--accent: #0ea5e9;
			--green: #22c55e;
			--yellow: #eab308;
			--red: #ef4444;
			--blue: #3b82f6;
			--purple: #a855f7;
			--muted: rgba(255,255,255,0.5);
		}
		body {
			font-family: var(--vscode-font-family, 'Segoe UI', system-ui, sans-serif);
			background: var(--bg);
			color: var(--fg);
			margin: 0;
			padding: 0;
		}
		/* HEADER */
		.header {
			background: var(--card-bg2);
			border-bottom: 1px solid var(--border);
			padding: 16px 24px;
			display: flex;
			justify-content: space-between;
			align-items: center;
			position: sticky;
			top: 0;
			z-index: 100;
		}
		.header-left { display: flex; align-items: center; gap: 12px; }
		.header-logo { font-size: 28px; line-height: 1; }
		.header-title { font-size: 18px; font-weight: 700; margin: 0; }
		.header-sub { font-size: 11px; color: var(--muted); margin: 0; }
		.version-badge {
			background: rgba(14,165,233,0.15);
			border: 1px solid rgba(14,165,233,0.4);
			color: var(--accent);
			font-size: 11px;
			font-weight: 600;
			padding: 2px 10px;
			border-radius: 20px;
		}
		.btn-group { display: flex; gap: 8px; }
		button {
			background: var(--vscode-button-background, #0e7490);
			color: var(--vscode-button-foreground, #fff);
			border: none;
			padding: 7px 16px;
			border-radius: 5px;
			cursor: pointer;
			font-size: 12px;
			font-weight: 500;
			display: flex;
			align-items: center;
			gap: 5px;
			transition: opacity 0.15s;
		}
		button:hover { opacity: 0.85; }
		button.secondary {
			background: var(--vscode-button-secondaryBackground, #3a3d41);
			color: var(--vscode-button-secondaryForeground, #ccc);
		}
		/* CONTENT */
		.content { padding: 24px; max-width: 1400px; }
		/* KPI */
		.kpi-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 14px;
			margin-bottom: 28px;
		}
		.kpi-card {
			background: var(--card-bg);
			border: 1px solid var(--border);
			border-radius: 8px;
			padding: 18px 20px;
			position: relative;
			overflow: hidden;
		}
		.kpi-card::before {
			content: '';
			position: absolute;
			top: 0; left: 0; right: 0;
			height: 3px;
		}
		.kpi-card.green::before { background: var(--green); }
		.kpi-card.red::before { background: var(--red); }
		.kpi-card.yellow::before { background: var(--yellow); }
		.kpi-card.blue::before { background: var(--blue); }
		.kpi-card.purple::before { background: var(--purple); }
		.kpi-icon { font-size: 22px; margin-bottom: 8px; }
		.kpi-value { font-size: 32px; font-weight: 700; line-height: 1; }
		.kpi-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
		/* FINDINGS */
		.findings-row {
			display: flex;
			gap: 8px;
			margin-top: 8px;
			flex-wrap: wrap;
		}
		.finding-chip {
			display: inline-flex;
			align-items: center;
			gap: 4px;
			padding: 2px 8px;
			border-radius: 4px;
			font-size: 11px;
			font-weight: 600;
		}
		.chip-red { background: rgba(239,68,68,0.15); color: var(--red); }
		.chip-yellow { background: rgba(234,179,8,0.15); color: var(--yellow); }
		.chip-blue { background: rgba(59,130,246,0.15); color: var(--blue); }
		/* SIMULATOR */
		.section-card {
			background: var(--card-bg);
			border: 1px solid var(--border);
			border-radius: 8px;
			padding: 20px;
			margin-bottom: 20px;
		}
		.section-header {
			display: flex;
			align-items: center;
			gap: 10px;
			margin-bottom: 14px;
		}
		.section-header h2 {
			font-size: 15px;
			font-weight: 600;
			margin: 0;
		}
		.section-header .section-desc {
			font-size: 12px;
			color: var(--muted);
		}
		.sim-form {
			display: flex;
			gap: 10px;
			align-items: center;
			flex-wrap: wrap;
		}
		.sim-form label { font-size: 11px; color: var(--muted); font-weight: 500; }
		.sim-group { display: flex; flex-direction: column; gap: 4px; }
		select, input[type="text"] {
			background: var(--vscode-input-background, #3c3c3c);
			color: var(--vscode-input-foreground, #d4d4d4);
			border: 1px solid var(--vscode-input-border, #555);
			padding: 7px 10px;
			border-radius: 5px;
			font-size: 13px;
			outline: none;
		}
		select:focus, input[type="text"]:focus {
			border-color: var(--accent);
		}
		input[type="text"].path-input { min-width: 260px; }
		input[type="text"].roles-input { min-width: 280px; }
		.sim-btn {
			align-self: flex-end;
			background: linear-gradient(135deg, #0ea5e9, #3b82f6);
			padding: 8px 20px;
			font-size: 13px;
			border-radius: 5px;
			font-weight: 600;
		}
		.sim-result {
			margin-top: 14px;
			padding: 14px 18px;
			border-radius: 6px;
			font-size: 13px;
			display: none;
			border-left: 4px solid;
		}
		.sim-result.allow {
			background: rgba(34,197,94,0.1);
			border-color: var(--green);
		}
		.sim-result.deny {
			background: rgba(239,68,68,0.1);
			border-color: var(--red);
		}
		.sim-result.noroute {
			background: rgba(234,179,8,0.1);
			border-color: var(--yellow);
		}
		.sim-verdict {
			font-size: 15px;
			font-weight: 700;
			margin-bottom: 6px;
		}
		.sim-detail { font-size: 12px; color: var(--muted); }
		.sim-matched-rule {
			display: inline-flex;
			align-items: center;
			gap: 5px;
			background: rgba(255,255,255,0.06);
			border-radius: 4px;
			padding: 3px 8px;
			font-size: 11px;
			margin-top: 6px;
		}
		.sim-matched-rule code { font-family: monospace; }
		/* TABLE */
		.table-controls {
			display: flex;
			gap: 10px;
			margin-bottom: 12px;
			align-items: center;
			flex-wrap: wrap;
		}
		.table-controls input[type="text"] { flex: 1; min-width: 200px; }
		.results-count { font-size: 12px; color: var(--muted); margin-left: auto; }
		table {
			width: 100%;
			border-collapse: collapse;
			font-size: 13px;
		}
		thead tr {
			background: var(--card-bg2);
			border-bottom: 2px solid var(--border);
		}
		th {
			padding: 10px 14px;
			text-align: left;
			font-size: 11px;
			font-weight: 600;
			color: var(--muted);
			text-transform: uppercase;
			letter-spacing: 0.04em;
		}
		td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
		tr:last-child td { border-bottom: none; }
		tbody tr:hover { background: rgba(255,255,255,0.025); }
		.method-badge {
			display: inline-block;
			padding: 2px 7px;
			border-radius: 4px;
			font-size: 10px;
			font-weight: 700;
			font-family: monospace;
		}
		.method-GET { background: rgba(34,197,94,0.15); color: var(--green); }
		.method-POST { background: rgba(59,130,246,0.15); color: var(--blue); }
		.method-PUT { background: rgba(234,179,8,0.15); color: var(--yellow); }
		.method-DELETE { background: rgba(239,68,68,0.15); color: var(--red); }
		.method-PATCH { background: rgba(168,85,247,0.15); color: var(--purple); }
		.method-ANY { background: rgba(255,255,255,0.08); color: var(--muted); }
		.access-badge {
			display: inline-flex;
			align-items: center;
			gap: 4px;
			padding: 3px 9px;
			border-radius: 12px;
			font-size: 11px;
			font-weight: 600;
			text-transform: uppercase;
		}
		.access-public { background: rgba(34,197,94,0.15); color: var(--green); border: 1px solid rgba(34,197,94,0.3); }
		.access-auth { background: rgba(234,179,8,0.15); color: var(--yellow); border: 1px solid rgba(234,179,8,0.3); }
		.access-role { background: rgba(59,130,246,0.15); color: var(--blue); border: 1px solid rgba(59,130,246,0.3); }
		.access-deny { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
		.access-unmatched { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
		.access-custom { background: rgba(168,85,247,0.15); color: var(--purple); border: 1px solid rgba(168,85,247,0.3); }
		code { background: rgba(255,255,255,0.07); padding: 1px 5px; border-radius: 3px; font-family: monospace; font-size: 12px; }
		.path-cell { font-family: monospace; font-size: 12px; }
		.no-data {
			padding: 40px;
			text-align: center;
			color: var(--muted);
		}
		.no-data-icon { font-size: 40px; margin-bottom: 10px; }
		/* FINDINGS TABLE */
		.finding-row-error td { border-left: 3px solid var(--red); }
		.finding-row-warning td:first-child { border-left: 3px solid var(--yellow); }
		.finding-row-info td:first-child { border-left: 3px solid var(--blue); }
		.sev-error { color: var(--red); font-weight: 700; }
		.sev-warning { color: var(--yellow); font-weight: 700; }
		.sev-info { color: var(--blue); font-weight: 700; }
		/* TABS */
		.tabs { display: flex; gap: 0; margin-bottom: 0; border-bottom: 1px solid var(--border); }
		.tab {
			padding: 10px 20px;
			cursor: pointer;
			font-size: 13px;
			font-weight: 500;
			color: var(--muted);
			border-bottom: 2px solid transparent;
			margin-bottom: -1px;
			transition: all 0.15s;
			user-select: none;
		}
		.tab:hover { color: var(--fg); }
		.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
		.tab-content { display: none; padding-top: 16px; }
		.tab-content.active { display: block; }
	</style>
</head>
<body>
<div class="header">
	<div class="header-left">
		<div class="header-logo">🛡️</div>
		<div>
			<p class="header-title">Spring Security Dashboard</p>
			<p class="header-sub">Static Analysis &amp; Authorization Matrix</p>
		</div>
		<span class="version-badge">${versionLabel}</span>
	</div>
	<div class="btn-group">
		<button onclick="exportMarkdown()">📄 Markdown</button>
		<button class="secondary" onclick="exportJson()">💾 JSON</button>
	</div>
</div>

<div class="content">
	<!-- KPIs -->
	<div class="kpi-grid">
		<div class="kpi-card blue">
			<div class="kpi-icon">🌐</div>
			<div class="kpi-value">${summary.routes.length}</div>
			<div class="kpi-label">Security Matchers</div>
		</div>
		<div class="kpi-card purple">
			<div class="kpi-icon">📡</div>
			<div class="kpi-value">${summary.endpoints.length}</div>
			<div class="kpi-label">Controller Endpoints</div>
		</div>
		<div class="kpi-card ${errorsCount > 0 ? 'red' : warningsCount > 0 ? 'yellow' : 'green'}">
			<div class="kpi-icon">${errorsCount > 0 ? '🚨' : warningsCount > 0 ? '⚠️' : '✅'}</div>
			<div class="kpi-value">${summary.findings.length}</div>
			<div class="kpi-label">Security Findings</div>
			<div class="findings-row">
				${errorsCount > 0 ? `<span class="finding-chip chip-red">⛔ ${errorsCount} Error${errorsCount > 1 ? 's' : ''}</span>` : ''}
				${warningsCount > 0 ? `<span class="finding-chip chip-yellow">⚠️ ${warningsCount} Warning${warningsCount > 1 ? 's' : ''}</span>` : ''}
				${infoCount > 0 ? `<span class="finding-chip chip-blue">ℹ️ ${infoCount} Info</span>` : ''}
			</div>
		</div>
		<div class="kpi-card green">
			<div class="kpi-icon">🔍</div>
			<div class="kpi-value">${summary.components.length}</div>
			<div class="kpi-label">Security Components</div>
		</div>
	</div>

	<!-- SIMULATOR -->
	<div class="section-card">
		<div class="section-header">
			<span style="font-size:20px">🎯</span>
			<div>
				<h2>Request Authorization Simulator</h2>
				<div class="section-desc">Simulate how Spring Security evaluates a request — tested directly against your security rules.</div>
			</div>
		</div>
		<div class="sim-form">
			<div class="sim-group">
				<label>HTTP Method</label>
				<select id="simMethod">
					<option value="GET">GET</option>
					<option value="POST">POST</option>
					<option value="PUT">PUT</option>
					<option value="DELETE">DELETE</option>
					<option value="PATCH">PATCH</option>
				</select>
			</div>
			<div class="sim-group">
				<label>Request Path</label>
				<input type="text" id="simPath" class="path-input" placeholder="/api/users/123" value="/api/users" />
			</div>
			<div class="sim-group">
				<label>User Roles (comma-separated)</label>
				<input type="text" id="simRoles" class="roles-input" placeholder="ROLE_USER, ROLE_ADMIN" value="" />
			</div>
			<button class="sim-btn" onclick="runSimulation()">▶ Test</button>
		</div>
		<div id="simResult" class="sim-result"></div>
	</div>

	<!-- TABBED CONTENT -->
	<div class="section-card" style="padding: 0; overflow: hidden;">
		<div class="tabs">
			<div class="tab active" onclick="switchTab(this, 'tab-matrix')">🌐 Access Matrix</div>
			<div class="tab" onclick="switchTab(this, 'tab-findings')">⚠️ Findings (${summary.findings.length})</div>
		</div>

		<!-- Matrix Tab -->
		<div id="tab-matrix" class="tab-content active" style="padding: 16px;">
			<div class="table-controls">
				<input type="text" id="filterInput" placeholder="🔍  Filter by path, method, or controller..." oninput="filterTable()" />
				<select id="accessFilter" onchange="filterTable()">
					<option value="ALL">All Access Levels</option>
					<option value="PUBLIC">Public (permitAll)</option>
					<option value="AUTHENTICATED">Authenticated</option>
					<option value="ROLE">Role Required</option>
					<option value="DENY">Deny All</option>
					<option value="UNMATCHED">Unmatched</option>
				</select>
				<span class="results-count" id="resultsCount"></span>
			</div>
			<table id="matrixTable">
				<thead>
					<tr>
						<th>Method</th>
						<th>Endpoint</th>
						<th>Controller</th>
						<th>Matched Rule</th>
						<th>Access</th>
						<th>Required</th>
					</tr>
				</thead>
				<tbody id="matrixBody"></tbody>
			</table>
		</div>

		<!-- Findings Tab -->
		<div id="tab-findings" class="tab-content" style="padding: 16px;">
			<table id="findingsTable">
				<thead>
					<tr>
						<th>Severity</th>
						<th>Rule ID</th>
						<th>CWE</th>
						<th>Message</th>
						<th>Location</th>
					</tr>
				</thead>
				<tbody id="findingsBody"></tbody>
			</table>
		</div>
	</div>
</div>

<script>
	const vscode = acquireVsCodeApi();
	const routes = ${routesJson};
	const endpoints = ${endpointsJson};
	const findings = ${findingsJson};
	const components = ${JSON.stringify(summary.components)};

	/* ---- TAB LOGIC ---- */
	function switchTab(el, id) {
		document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
		document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
		el.classList.add('active');
		document.getElementById(id).classList.add('active');
	}

	/* ---- SIMULATION (pure client-side) ---- */
	function normalizePath(p) {
		let r = (p || '').trim();
		if (!r.startsWith('/')) r = '/' + r;
		if (r.length > 1 && r.endsWith('/')) r = r.slice(0, -1);
		return r;
	}

	function matchesPattern(pattern, path) {
		if (!pattern) return false;
		if (pattern.includes('anyRequest')) return true;
		if (pattern === '/**') return true;
		const normPat = normalizePath(pattern);
		const normPath = normalizePath(path);
		if (normPat === normPath) return true;

		// Build regex step by step (avoid regex literals inside TS template strings)
		let regexStr = normPat;
		// Escape special regex chars except { } which we handle next
		regexStr = regexStr.split('').map(function(c) {
			if (['.', '+', '?', '^', '$', '(', ')', '|', '[', ']', '\\\\'].indexOf(c) >= 0) return '\\\\' + c;
			return c;
		}).join('');
		// {pathVar} => [^/]+
		regexStr = regexStr.replace(new RegExp('\\\\{[^}]+\\\\}', 'g'), '[^/]+');
		// /** => optional trailing segment
		regexStr = regexStr.replace(new RegExp('/\\\\*\\\\*', 'g'), '(?:/.*)?');
		// /* => single segment wildcard
		regexStr = regexStr.replace(new RegExp('/\\\\*(?!\\\\*)', 'g'), '/[^/]+');

		try {
			return new RegExp('^' + regexStr + '$').test(normPath);
		} catch(e) {
			return false;
		}
	}

	function parseRoles(rolesStr) {
		return rolesStr.split(',').map(r => r.trim()).filter(Boolean);
	}

	function normalizeRole(r) {
		return r.startsWith('ROLE_') ? r : 'ROLE_' + r;
	}

	function simulate(method, path, userRoles) {
		if (routes.length === 0) {
			return {
				verdict: 'noroute',
				icon: '⚠️',
				title: 'No Routes Configured',
				message: 'No security matchers found in the project. Open a Spring project with Spring Security and refresh the analysis.',
				matchedPattern: null
			};
		}

		for (const route of routes) {
			const methodMatch = route.method === 'ANY' || route.method === method;
			if (!methodMatch) continue;
			if (!matchesPattern(route.pattern, path)) continue;

			const al = route.accessLevel;
			const reqs = route.requiredRolesOrAuthorities || [];

			if (al === 'permitAll' || al === 'anonymous') {
				return { verdict: 'allow', icon: '✅', title: 'ACCESS ALLOWED',
					message: 'Route is publicly accessible — no authentication required.',
					matchedPattern: route.pattern };
			}
			if (al === 'denyAll') {
				return { verdict: 'deny', icon: '❌', title: 'ACCESS DENIED',
					message: 'Route is explicitly blocked for all users (denyAll).',
					matchedPattern: route.pattern };
			}
			if (al === 'authenticated' || al === 'fullyAuthenticated' || al === 'rememberMe') {
				const ok = userRoles.length > 0;
				return {
					verdict: ok ? 'allow' : 'deny',
					icon: ok ? '✅' : '❌',
					title: ok ? 'ACCESS ALLOWED' : 'ACCESS DENIED',
					message: ok
						? \`User is authenticated (roles: \${userRoles.join(', ') || 'none provided'}).\`
						: 'Endpoint requires authentication. Provide at least one role to simulate an authenticated user.',
					matchedPattern: route.pattern
				};
			}
			if (al === 'hasRole' || al === 'hasAnyRole') {
				const normalizedRequired = reqs.map(normalizeRole);
				const normalizedUser = userRoles.map(normalizeRole);
				const ok = normalizedRequired.some(r => normalizedUser.includes(r));
				return {
					verdict: ok ? 'allow' : 'deny',
					icon: ok ? '✅' : '❌',
					title: ok ? 'ACCESS ALLOWED' : 'ACCESS DENIED',
					message: ok
						? \`User role(s) [\${userRoles.join(', ')}] satisfy required [\${normalizedRequired.join(', ')}].\`
						: \`User role(s) [\${userRoles.join(', ')}] do not include any of required [\${normalizedRequired.join(', ')}].\`,
					matchedPattern: route.pattern
				};
			}
			if (al === 'hasAuthority' || al === 'hasAnyAuthority') {
				const ok = reqs.some(a => userRoles.includes(a));
				return {
					verdict: ok ? 'allow' : 'deny',
					icon: ok ? '✅' : '❌',
					title: ok ? 'ACCESS ALLOWED' : 'ACCESS DENIED',
					message: ok
						? \`User has required authority [\${reqs.join(', ')}].\`
						: \`User authorities [\${userRoles.join(', ')}] do not include [\${reqs.join(', ')}].\`,
					matchedPattern: route.pattern
				};
			}
			// custom / access() SpEL
			return {
				verdict: 'allow',
				icon: '⚡',
				title: 'CUSTOM RULE MATCHED',
				message: \`Route matched a custom expression-based rule (\${al}). Manual review required.\`,
				matchedPattern: route.pattern
			};
		}

		return {
			verdict: 'deny',
			icon: '❌',
			title: 'ACCESS DENIED',
			message: 'No security rule matched this request. Spring Security denies all unmatched requests by default.',
			matchedPattern: null
		};
	}

	function runSimulation() {
		const method = document.getElementById('simMethod').value;
		const path = document.getElementById('simPath').value.trim();
		const rolesRaw = document.getElementById('simRoles').value;
		const roles = parseRoles(rolesRaw);

		if (!path) {
			alert('Please enter a request path.');
			return;
		}

		const result = simulate(method, path, roles);
		const div = document.getElementById('simResult');
		div.style.display = 'block';
		div.className = 'sim-result ' + result.verdict;

		const matchHtml = result.matchedPattern
			? \`<div class="sim-matched-rule">📌 Matched rule: <code>\${result.matchedPattern}</code></div>\`
			: \`<div class="sim-matched-rule" style="color:var(--muted)">No explicit matcher found</div>\`;

		div.innerHTML = \`
			<div class="sim-verdict">\${result.icon} \${result.title}</div>
			<div class="sim-detail">\${result.message}</div>
			\${matchHtml}
		\`;
	}

	/* ---- MATRIX ---- */
	function getAccessBadge(accessLevel) {
		const map = {
			permitAll: ['access-public', '🔓 Public'],
			anonymous: ['access-public', '🔓 Public'],
			authenticated: ['access-auth', '🔑 Auth'],
			fullyAuthenticated: ['access-auth', '🔑 Auth'],
			rememberMe: ['access-auth', '🔑 Auth'],
			hasRole: ['access-role', '🛡 Role'],
			hasAnyRole: ['access-role', '🛡 Role'],
			hasAuthority: ['access-role', '🔐 Authority'],
			hasAnyAuthority: ['access-role', '🔐 Authority'],
			denyAll: ['access-deny', '⛔ Deny'],
			custom: ['access-custom', '⚡ Custom'],
			unmatched: ['access-unmatched', '❓ Unmatched'],
		};
		return map[accessLevel] || ['access-custom', accessLevel];
	}

	function getMethodBadge(method) {
		return \`<span class="method-badge method-\${method}">\${method}</span>\`;
	}

	function findMatchingRoute(method, path) {
		for (const r of routes) {
			if (r.method !== 'ANY' && r.method !== method) continue;
			if (matchesPattern(r.pattern, path)) return r;
		}
		return null;
	}

	function renderMatrix() {
		const tbody = document.getElementById('matrixBody');
		tbody.innerHTML = '';

		const items = endpoints.length > 0
			? endpoints
			: routes.map(r => ({
				httpMethod: r.method,
				fullPath: r.pattern,
				controllerClass: '—',
				methodName: '',
				file: r.file,
				line: r.line
			}));

		if (items.length === 0) {
			tbody.innerHTML = '<tr><td colspan="6"><div class="no-data"><div class="no-data-icon">🔎</div><div>No security data found. Open a Spring project and run Refresh Analysis.</div></div></td></tr>';
			updateResultsCount(0);
			return;
		}

		for (const item of items) {
			const matched = findMatchingRoute(item.httpMethod, item.fullPath);
			const al = matched ? matched.accessLevel : 'unmatched';
			const [badgeClass, badgeText] = getAccessBadge(al);
			const reqs = matched?.requiredRolesOrAuthorities?.join(', ') || '—';
			const tr = document.createElement('tr');
			tr.setAttribute('data-access', al);
			tr.innerHTML = \`
				<td>\${getMethodBadge(item.httpMethod)}</td>
				<td class="path-cell">\${item.fullPath}</td>
				<td style="color:var(--muted);font-size:12px">\${item.controllerClass}\${item.methodName ? '::' + item.methodName + '()' : ''}</td>
				<td><code>\${matched ? matched.pattern : 'none'}</code></td>
				<td><span class="access-badge \${badgeClass}">\${badgeText}</span></td>
				<td style="font-size:12px;color:var(--muted)">\${reqs}</td>
			\`;
			tbody.appendChild(tr);
		}
		updateResultsCount(items.length);
	}

	function filterTable() {
		const q = document.getElementById('filterInput').value.toLowerCase();
		const af = document.getElementById('accessFilter').value;
		let visible = 0;
		document.querySelectorAll('#matrixBody tr[data-access]').forEach(row => {
			const text = row.textContent.toLowerCase();
			const access = row.getAttribute('data-access') || '';
			const matchesQ = !q || text.includes(q);
			let matchesA = true;
			if (af === 'PUBLIC') matchesA = access === 'permitAll' || access === 'anonymous';
			else if (af === 'AUTHENTICATED') matchesA = ['authenticated','fullyAuthenticated','rememberMe'].includes(access);
			else if (af === 'ROLE') matchesA = access.includes('Role') || access.includes('Authority');
			else if (af === 'DENY') matchesA = access === 'denyAll';
			else if (af === 'UNMATCHED') matchesA = access === 'unmatched';
			const show = matchesQ && matchesA;
			row.style.display = show ? '' : 'none';
			if (show) visible++;
		});
		updateResultsCount(visible);
	}

	function updateResultsCount(n) {
		const el = document.getElementById('resultsCount');
		if (el) el.textContent = n + ' row' + (n !== 1 ? 's' : '');
	}

	/* ---- FINDINGS TABLE ---- */
	function renderFindings() {
		const tbody = document.getElementById('findingsBody');
		if (!findings.length) {
			tbody.innerHTML = '<tr><td colspan="5"><div class="no-data"><div class="no-data-icon">✅</div><div>No security findings detected. Great job!</div></div></td></tr>';
			return;
		}
		for (const f of findings) {
			const sevClass = f.severity === 'error' ? 'sev-error' : f.severity === 'warning' ? 'sev-warning' : 'sev-info';
			const sevIcon = f.severity === 'error' ? '⛔' : f.severity === 'warning' ? '⚠️' : 'ℹ️';
			const fname = f.file && f.file.fsPath ? f.file.fsPath.split(/[\\\\/]/).pop() : '—';
			const tr = document.createElement('tr');
			tr.className = 'finding-row-' + f.severity;
			tr.innerHTML = \`
				<td><span class="\${sevClass}">\${sevIcon} \${f.severity.toUpperCase()}</span></td>
				<td><code style="font-size:11px">\${f.ruleId}</code></td>
				<td><code style="font-size:11px;color:var(--muted)">\${f.cweId || '—'}</code></td>
				<td style="max-width:380px">\${f.message}</td>
				<td style="font-size:11px;color:var(--muted);white-space:nowrap">\${fname}:\${f.line}</td>
			\`;
			tbody.appendChild(tr);
		}
	}

	function exportMarkdown() { vscode.postMessage({ command: 'exportMarkdown' }); }
	function exportJson() { vscode.postMessage({ command: 'exportJson' }); }

	renderMatrix();
	renderFindings();
</script>
</body>
</html>`;
	}

	public dispose(): void {
		SecurityDashboardPanel.currentPanel = undefined;
		this.panel.dispose();
		while (this.disposables.length) {
			const x = this.disposables.pop();
			if (x) {
				x.dispose();
			}
		}
	}
}

function generateMarkdownReport(summary: SecuritySummary): string {
	const lines: string[] = [
		`# 🛡️ Spring Security Audit Report`,
		``,
		`*Generated by Spring Security Inspector on ${new Date().toLocaleString()}*`,
		``,
		`## Summary`,
		`- **Spring Security Version:** ${summary.springSecurityVersion}`,
		`- **Security Matchers:** ${summary.routes.length}`,
		`- **Controller Endpoints:** ${summary.endpoints.length}`,
		`- **Total Findings:** ${summary.findings.length} (${summary.findings.filter(f => f.severity === 'error').length} Errors, ${summary.findings.filter(f => f.severity === 'warning').length} Warnings)`,
		``,
		`## Security Findings`,
	];

	if (summary.findings.length === 0) {
		lines.push(`✅ No security issues detected!`);
	} else {
		lines.push(`| Severity | Rule ID | CWE | Message | Location |`);
		lines.push(`|:---|:---|:---|:---|:---|`);
		for (const f of summary.findings) {
			lines.push(
				`| **${f.severity.toUpperCase()}** | \`${f.ruleId}\` | ${f.cweId || '-'} | ${f.message} | \`${f.file.fsPath}:${f.line}\` |`
			);
		}
	}

	lines.push(``, `## Routes Matrix`, `| Verb | Route Pattern | Access Requirement |`);
	lines.push(`|:---|:---|:---|`);
	for (const r of summary.routes) {
		const reqs = r.requiredRolesOrAuthorities ? ` (${r.requiredRolesOrAuthorities.join(', ')})` : '';
		lines.push(`| \`[${r.method}]\` | \`${r.pattern}\` | \`${r.accessLevel}${reqs}\` |`);
	}

	return lines.join('\n');
}
