export interface CleanedJava {
	cleanedText: string;
	originalText: string;
	/** Map from char offset in cleaned text to char offset in original text */
	offsetMap: number[];
}

/**
 * Strips comments from Java source code while preserving exact line breaks and offsets.
 * Replacing characters inside comments with spaces ensures that line numbers and offsets stay 1:1.
 */
export function cleanJavaSource(source: string): CleanedJava {
	const chars = source.split('');
	const len = chars.length;
	let inSingleLineComment = false;
	let inMultiLineComment = false;
	let inString = false;
	let inChar = false;
	let stringEscape = false;

	for (let i = 0; i < len; i++) {
		const char = chars[i];
		const next = i + 1 < len ? chars[i + 1] : '';

		if (inSingleLineComment) {
			if (char === '\n') {
				inSingleLineComment = false;
			} else {
				chars[i] = ' ';
			}
			continue;
		}

		if (inMultiLineComment) {
			if (char === '*' && next === '/') {
				chars[i] = ' ';
				chars[i + 1] = ' ';
				i++;
				inMultiLineComment = false;
			} else if (char !== '\n') {
				chars[i] = ' ';
			}
			continue;
		}

		if (inString) {
			if (stringEscape) {
				stringEscape = false;
			} else if (char === '\\') {
				stringEscape = true;
			} else if (char === '"') {
				inString = false;
			}
			continue;
		}

		if (inChar) {
			if (stringEscape) {
				stringEscape = false;
			} else if (char === '\\') {
				stringEscape = true;
			} else if (char === '\'') {
				inChar = false;
			}
			continue;
		}

		// Check start of string or char
		if (char === '"') {
			inString = true;
			continue;
		}
		if (char === '\'') {
			inChar = true;
			continue;
		}

		// Check start of comments
		if (char === '/' && next === '/') {
			inSingleLineComment = true;
			chars[i] = ' ';
			chars[i + 1] = ' ';
			i++;
			continue;
		}

		if (char === '/' && next === '*') {
			inMultiLineComment = true;
			chars[i] = ' ';
			chars[i + 1] = ' ';
			i++;
			continue;
		}
	}

	const cleaned = chars.join('');
	return {
		cleanedText: cleaned,
		originalText: source,
		offsetMap: Array.from({ length: len }, (_, i) => i),
	};
}

export interface LineColumn {
	line: number; // 1-indexed
	column: number; // 1-indexed
}

export function offsetToLineColumn(text: string, offset: number): LineColumn {
	const clamped = Math.max(0, Math.min(offset, text.length));
	let line = 1;
	let column = 1;

	for (let i = 0; i < clamped; i++) {
		if (text[i] === '\n') {
			line++;
			column = 1;
		} else {
			column++;
		}
	}

	return { line, column };
}
