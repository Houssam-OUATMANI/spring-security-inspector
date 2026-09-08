import { SecurityFinding } from '../models/finding';

interface Suppression {
	ruleId: string;
	line: number;
	reason?: string;
}

/**
 * Extracts suppression comments like:
 * // @ssi-ignore SPRING_SEC_CSRF_DISABLED: reason
 * // @spring-security-ignore SPRING_SEC_CSRF_DISABLED
 */
export function extractSuppressions(originalText: string): Suppression[] {
	const suppressions: Suppression[] = [];
	const lines = originalText.split('\n');

	for (let i = 0; i < lines.length; i++) {
		const lineText = lines[i];
		const match = /(?:\/\/|\/\*)\s*@(?:ssi-ignore|spring-security-ignore)\s+([A-Z0-9_]+)(?::\s*([^*]+))?/i.exec(
			lineText
		);

		if (match) {
			suppressions.push({
				ruleId: match[1].toUpperCase(),
				line: i + 1, // 1-indexed
				reason: match[2]?.trim(),
			});
		}
	}

	return suppressions;
}

/**
 * Filters out findings that match an inline suppression on the finding line or the line immediately before.
 */
export function filterSuppressedFindings(
	findings: SecurityFinding[],
	suppressions: Suppression[]
): SecurityFinding[] {
	if (suppressions.length === 0) {
		return findings;
	}

	return findings.filter(finding => {
		const isSuppressed = suppressions.some(
			sup =>
				(sup.ruleId === finding.ruleId || sup.ruleId === 'ALL') &&
				(sup.line === finding.line || sup.line === finding.line - 1)
		);
		return !isSuppressed;
	});
}
