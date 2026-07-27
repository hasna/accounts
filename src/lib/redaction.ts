const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)\s+[^\s,;}\]]+|[^\s,;}\]]+)/gi;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(?:authorization|proxy-authorization|cookie|set-cookie)\2\s*[:=]\s*/gim;
const SERIALIZED_FIELD_BOUNDARY = /^,\s*["']?[A-Za-z][A-Za-z0-9_-]*["']?\s*:/;

function quotedValueEnd(value: string, start: number, quote: string): number {
  for (let index = start + 1; index < value.length; index++) {
    if (value[index] === "\r" || value[index] === "\n") return index;
    if (value[index] === "\\") {
      index++;
      continue;
    }
    if (value[index] === quote) return index + 1;
  }
  return value.length;
}

function unquotedHeaderValueEnd(value: string, start: number): number {
  let quote: string | undefined;
  for (let index = start; index < value.length; index++) {
    const char = value[index]!;
    if (char === "\r" || char === "\n") return index;
    if (quote) {
      if (char === "\\") {
        index++;
      } else if (char === quote) {
        quote = undefined;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "}" || char === "]") return index;
    if (char === "," && SERIALIZED_FIELD_BOUNDARY.test(value.slice(index))) return index;
  }
  return value.length;
}

function redactSensitiveRequestHeaders(value: string): string {
  let cursor = 0;
  let output = "";
  SENSITIVE_REQUEST_HEADER_PATTERN.lastIndex = 0;

  for (let match = SENSITIVE_REQUEST_HEADER_PATTERN.exec(value); match; match = SENSITIVE_REQUEST_HEADER_PATTERN.exec(value)) {
    const valueStart = SENSITIVE_REQUEST_HEADER_PATTERN.lastIndex;
    const openingQuote = value[valueStart];
    const valueEnd =
      openingQuote === '"' || openingQuote === "'"
        ? quotedValueEnd(value, valueStart, openingQuote)
        : unquotedHeaderValueEnd(value, valueStart);
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
