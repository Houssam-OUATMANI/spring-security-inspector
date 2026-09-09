import * as vscode from 'vscode';
import { SpringSecurityVersion } from '../models/summary';

export interface ProjectDetectionResult {
	projectDetected: boolean;
	springSecurityVersion: SpringSecurityVersion;
	buildFiles: vscode.Uri[];
}

export async function detectProject(): Promise<ProjectDetectionResult> {
	const [pom, gradle, gradleKts] = await Promise.all([
		vscode.workspace.findFiles('**/pom.xml', '**/target/**', 10),
		vscode.workspace.findFiles('**/build.gradle', '**/build/**', 10),
		vscode.workspace.findFiles('**/build.gradle.kts', '**/build/**', 10),
	]);

	const buildFiles = [...pom, ...gradle, ...gradleKts];
	if (buildFiles.length === 0) {
		return {
			projectDetected: false,
			springSecurityVersion: 'unknown',
			buildFiles: [],
		};
	}

	let projectDetected = false;
	let springSecurityVersion: SpringSecurityVersion = 'unknown';

	for (const file of buildFiles) {
		try {
			const doc = await vscode.workspace.openTextDocument(file);
			const text = doc.getText();

			if (hasSpringSecurityDependency(text)) {
				projectDetected = true;

				// Check version clues (Spring Boot 3.x uses Spring Security 6.x)
				if (/spring-boot[^\n]*3\.\d+(?:\.\d+)?/i.test(text) || /id\s*\(?["']org\.springframework\.boot["']\)?\s*version\s*["']3\./i.test(text)) {
					springSecurityVersion = 'spring-security-6';
				} else if (/spring-boot[^\n]*2\.\d+(?:\.\d+)?/i.test(text) || /id\s*\(?["']org\.springframework\.boot["']\)?\s*version\s*["']2\./i.test(text)) {
					springSecurityVersion = 'spring-security-5';
				} else if (/spring-security.*6\.\d+/i.test(text)) {
					springSecurityVersion = 'spring-security-6';
				} else if (/spring-security.*5\.\d+/i.test(text)) {
					springSecurityVersion = 'spring-security-5';
				}
			}
		} catch {
			// Ignore read errors on inaccessible files
		}
	}

	return {
		projectDetected,
		springSecurityVersion,
		buildFiles,
	};
}

function hasSpringSecurityDependency(text: string): boolean {
	return /spring-security|spring-boot-starter-security/.test(text);
}
