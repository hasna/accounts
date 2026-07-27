const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?[ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)[ \t]+[^\s,;}\]]+|[^\s,;}\]]+)/gi;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(?:authorization|proxy-authorization|cookie|set-cookie)\2[ \t]*[:=][ \t]*/gim;
const SERIALIZED_FIELD_BOUNDARY = /^,[ \t]*["']?[A-Za-z][A-Za-z0-9_-]*["']?[ \t]*:/;

function lineBreakEnd(value: string, start: number): number {
  return value[start] === "\r" && value[start + 1] === "\n" ? start + 2 : start + 1;
}

function continuationStart(value: string, lineBreakStart: number): number | undefined {
  const nextLine = lineBreakEnd(value, lineBreakStart);
  return value[nextLine] === " " || value[nextLine] === "\t" ? nextLine : undefined;
}

function quotedValueEnd(value: string, start: number, quote: string): number {
  for (let index = start + 1; index < value.length; index++) {
    if (value[index] === "\r" || value[index] === "\n") {
      const continuation = continuationStart(value, index);
      if (continuation === undefined) return index;
      index = continuation - 1;
      continue;
    }
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
    if (char === "\r" || char === "\n") {
      const continuation = continuationStart(value, index);
      if (continuation === undefined) return index;
      index = continuation - 1;
      continue;
    }
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
