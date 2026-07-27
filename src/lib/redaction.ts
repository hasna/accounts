const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?[ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)[ \t]+[^\s,;]+|[^\s,;]+)/gi;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(authorization|proxy-authorization|cookie|set-cookie)\2[ \t]*[:=][ \t]*/gim;
const SERIALIZED_FIELD_BOUNDARY = /^,[ \t]*["']?[A-Za-z][A-Za-z0-9_-]*["']?[ \t]*:/;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const FIELD_ASSIGNMENT_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*=/;
const AUTH_PARAMETER_PATTERN =
  /^(?:credential|signedheaders|signature|username|realm|nonce|response|uri|algorithm|qop|nc|cnonce|opaque|charset|stale|userhash)[ \t]*=/i;
const INDEPENDENT_DIAGNOSTIC_PATTERN =
  /^(?:status|message|error|code|request[-_]?id|trace[-_]?id|span[-_]?id|attempt|retryable|completed|duration|elapsed|method|url|path|host|response|result|outcome|event|level|timestamp)[ \t]*[:=]/i;
const SET_COOKIE_ATTRIBUTE_PATTERN =
  /^(?:(?:expires|max-age|domain|path|samesite)[ \t]*=|(?:secure|httponly|partitioned)(?:[ \t]*[;,]|$))/i;

type SensitiveHeaderName = "authorization" | "proxy-authorization" | "cookie" | "set-cookie";

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

function isSyntacticContinuation(
  headerName: SensitiveHeaderName,
  previousLine: string,
  nextLine: string,
): boolean {
  const trimmed = nextLine.trim();
  if (!trimmed || HEADER_LINE_PATTERN.test(trimmed)) return false;

  if (headerName === "authorization" || headerName === "proxy-authorization") {
    if (!previousLine.trimEnd().endsWith(",")) return false;
    if (AUTH_PARAMETER_PATTERN.test(trimmed)) return true;
    return !INDEPENDENT_DIAGNOSTIC_PATTERN.test(trimmed) && FIELD_ASSIGNMENT_PATTERN.test(trimmed);
  }

  if (!/[;,][ \t]*$/.test(previousLine)) return false;
  if (headerName === "set-cookie" && SET_COOKIE_ATTRIBUTE_PATTERN.test(trimmed)) return true;
  return !INDEPENDENT_DIAGNOSTIC_PATTERN.test(trimmed) && FIELD_ASSIGNMENT_PATTERN.test(trimmed);
}

function continuationStart(
  value: string,
  lineBreakStart: number,
  lineStart: number,
  headerName: SensitiveHeaderName,
): number | undefined {
  const nextLine = lineBreakEnd(value, lineBreakStart);
  if (value[nextLine] !== " " && value[nextLine] !== "\t") return undefined;
  const nextEnd = nextLineEnd(value, nextLine);
  return isSyntacticContinuation(
    headerName,
    value.slice(lineStart, lineBreakStart),
    value.slice(nextLine, nextEnd),
  )
    ? nextLine
    : undefined;
}

function quotedValueEnd(
  value: string,
  start: number,
  quote: string,
  headerName: SensitiveHeaderName,
): number {
  let lineStart = start;
  for (let index = start + 1; index < value.length; index++) {
    if (value[index] === "\r" || value[index] === "\n") {
      const continuation = continuationStart(value, index, lineStart, headerName);
      if (continuation === undefined) return index;
      lineStart = continuation;
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

function unquotedHeaderValueEnd(
  value: string,
  start: number,
  headerName: SensitiveHeaderName,
): number {
  let quote: string | undefined;
  let lineStart = start;
  for (let index = start; index < value.length; index++) {
    const char = value[index]!;
    if (char === "\r" || char === "\n") {
      const continuation = continuationStart(value, index, lineStart, headerName);
      if (continuation === undefined) return index;
      lineStart = continuation;
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
    const headerName = match[3]!.toLowerCase() as SensitiveHeaderName;
    const valueEnd =
      openingQuote === '"' || openingQuote === "'"
        ? quotedValueEnd(value, valueStart, openingQuote, headerName)
        : unquotedHeaderValueEnd(value, valueStart, headerName);
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
