const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?[ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)[ \t]+[^\s,;]+|[^\s,;]+)/gi;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(authorization|proxy-authorization|cookie|set-cookie)\2[ \t]*[:=][ \t]*/gim;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const EXPLICIT_DIAGNOSTIC_RECORD_PATTERN =
  /^(?:status|message|stack|detail)[ \t]*=[ \t]*\S/i;

type FoldSeparator = "," | ";";

function lineBreakEnd(value: string, start: number): number {
  return value[start] === "\r" && value[start + 1] === "\n" ? start + 2 : start + 1;
}

function nextLineEnd(value: string, start: number): number {
  const cr = value.indexOf("\r", start);
  const lf = value.indexOf("\n", start);
  if (cr === -1) return lf === -1 ? value.length : lf;
  if (lf === -1) return cr;
  return Math.min(cr, lf);
}

function leadingFoldSeparator(
  value: string,
): { separator: FoldSeparator; remainder: string } | undefined {
  const match = /^([,;])[ \t]*(.*)$/.exec(value);
  if (!match) return undefined;
  return {
    separator: match[1] as FoldSeparator,
    remainder: match[2]!.trim(),
  };
}

function isSyntacticContinuation(
  sawContent: boolean,
  lastSignificant: string | undefined,
  nextLine: string,
): boolean {
  const trimmed = nextLine.trim();
  if (!trimmed || HEADER_LINE_PATTERN.test(trimmed)) return false;

  if (!sawContent) {
    return true;
  }

  const leadingSeparator = leadingFoldSeparator(trimmed);
  if (leadingSeparator) {
    return true;
  }

  if (lastSignificant === "," || lastSignificant === ";") {
    return true;
  }

  return !EXPLICIT_DIAGNOSTIC_RECORD_PATTERN.test(trimmed);
}

function sensitiveHeaderValueEnd(
  value: string,
  start: number,
): number {
  const wrapperQuote = value[start] === '"' || value[start] === "'" ? value[start] : undefined;
  let quote = wrapperQuote;
  let sawContent = false;
  let lastSignificant: string | undefined;

  for (let index = start + (wrapperQuote ? 1 : 0); index < value.length; index++) {
    const char = value[index]!;

    if (char === "\r" || char === "\n") {
      const nextLine = lineBreakEnd(value, index);
      if (value[nextLine] !== " " && value[nextLine] !== "\t") return index;
      const nextEnd = nextLineEnd(value, nextLine);
      if (
        !quote &&
        !isSyntacticContinuation(
          sawContent,
          lastSignificant,
          value.slice(nextLine, nextEnd),
        )
      ) {
        return index;
      }
      index = nextLine - 1;
      continue;
    }

    if (quote) {
      if (char === "\\") {
        if (index + 1 < value.length) index++;
        continue;
      }
      if (char === quote) {
        if (wrapperQuote) return index + 1;
        quote = undefined;
      }
      sawContent = true;
      if (char !== " " && char !== "\t") lastSignificant = char;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      sawContent = true;
      lastSignificant = char;
      continue;
    }
    if (char !== " " && char !== "\t") {
      sawContent = true;
      lastSignificant = char;
    }
  }

  return value.length;
}

function redactSensitiveRequestHeaders(value: string): string {
  let cursor = 0;
  let output = "";
  SENSITIVE_REQUEST_HEADER_PATTERN.lastIndex = 0;

  for (let match = SENSITIVE_REQUEST_HEADER_PATTERN.exec(value); match; match = SENSITIVE_REQUEST_HEADER_PATTERN.exec(value)) {
    const valueStart = SENSITIVE_REQUEST_HEADER_PATTERN.lastIndex;
    const valueEnd = sensitiveHeaderValueEnd(value, valueStart);
    if (valueEnd === valueStart) continue;
    output += value.slice(cursor, valueStart) + "[REDACTED]";
    cursor = valueEnd;
    SENSITIVE_REQUEST_HEADER_PATTERN.lastIndex = valueEnd;
  }

  return cursor === 0 ? value : output + value.slice(cursor);
}

/** Redact common credential values and credential-bearing request headers. */
export function redactText(value: string): string {
  return redactSensitiveRequestHeaders(value)
    .replace(SECRET_FIELD_PATTERN, "$1[REDACTED]")
    .replace(SECRET_PATTERN, "[REDACTED]");
}
