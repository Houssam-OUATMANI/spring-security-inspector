import * as vscode from 'vscode';
import { SecurityFinding } from '../models/finding';

export async function auditPropertiesFiles(): Promise<SecurityFinding[]> {
	const findings: SecurityFinding[] = [];
	const propFiles = await vscode.workspace.findFiles(
		'**/{application,bootstrap}*.{properties,yml,yaml}',
		'**/{target,build,node_modules}/**'
	);

	for (const file of propFiles) {
		try {
			const bytes = await vscode.workspace.fs.readFile(file);
			const text = Buffer.from(bytes).toString('utf8');
			const lines = text.split('\n');

			for (let i = 0; i < lines.length; i++) {
				const line = lines[i];
				const lineNum = i + 1;

				// Ignore commented lines
				if (line.trim().startsWith('#') || line.trim().startsWith('!')) {
					continue;
				}

				// 1. Actuator wildcards
				if (/management\.endpoints\.web\.exposure\.include\s*=\s*\*|include:\s*["']?\*["']?/i.test(line)) {
					findings.push({
						id: `actuator-wildcard-${file.fsPath}-${lineNum}`,
						message: "Spring Boot Actuator endpoints are completely exposed via wildcard '*'",
						ruleId: 'SPRING_SEC_ACTUATOR_WILDCARD_EXPOSURE',
						cweId: 'CWE-200',
						severity: 'warning',
						line: lineNum,
						column: 1,
						file,
						recommendation: "Explicitly list required actuator endpoints (e.g. 'health,info') instead of exposing all sensitive management endpoints.",
					});
				}

				// 2. Default hardcoded security password
				if (/spring\.security\.user\.password\s*=\s*([^\s#]+)/i.test(line) || /password:\s*["']?([^\s#"']+)["']?/i.test(line)) {
					const match = /password\s*[:=]\s*["']?([^\s#"']+)["']?/i.exec(line);
					if (match && !match[1].startsWith('${')) {
						findings.push({
							id: `hardcoded-password-${file.fsPath}-${lineNum}`,
							message: 'Hardcoded Spring Security password in configuration file',
							ruleId: 'SPRING_SEC_HARDCODED_DEFAULT_PASSWORD',
							cweId: 'CWE-256',
							severity: 'error',
							line: lineNum,
							column: 1,
							file,
							recommendation: 'Use environment variables (${SPRING_SECURITY_PASSWORD}) or a secure secrets vault rather than committing credentials in plain text.',
						});
					}
				}
			}
		} catch {
			// Ignore read error
		}
	}

	return findings;
}
