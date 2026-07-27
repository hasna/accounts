const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?[ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)[ \t]+[^\s,;]+|[^\s,;]+)/gi;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(authorization|proxy-authorization|cookie|set-cookie)\2[ \t]*[:=][ \t]*/gim;
const SERIALIZED_FIELD_BOUNDARY = /^,[ \t]*["']?[A-Za-z][A-Za-z0-9_-]*["']?[ \t]*:/;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const AUTH_PARAMETER_PATTERN =
  /^(?:credential|signedheaders|signature|username|realm|nonce|response|uri|algorithm|qop|nc|cnonce|opaque|charset|stale|userhash)[ \t]*=/i;
const SET_COOKIE_ATTRIBUTE_PATTERN =
  /^(?:(?:expires|max-age|domain|path|samesite)[ \t]*=|(?:secure|httponly|partitioned)(?:[ \t]*[;,]|$))/i;
const HTTP_TOKEN_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const AUTH_TOKEN68_PATTERN = /^[A-Za-z0-9._~+/-]+=*$/;
const AUTH_TOKEN68_PADDING_PATTERN = /^=+$/;
const ASSIGNMENT_RECORD_PATTERN =
  /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*=/;
const COOKIE_VALUE_FRAGMENT_PATTERN = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$/;
const COOKIE_VALUE_TAIL_PATTERN =
  /(?:^|;[ \t]*)[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*=[ \t]*(?:"[^"\r\n]*"|[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*)$/;
const AUTH_PARAMETER_TAIL_PATTERN =
  /(?:^|,[ \t]*)(?:credential|signedheaders|signature|username|realm|nonce|response|uri|algorithm|qop|nc|cnonce|opaque|charset|stale|userhash)[ \t]*=[ \t]*[^,\s]*$/i;

type SensitiveHeaderName = "authorization" | "proxy-authorization" | "cookie" | "set-cookie";
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

function unfoldedHeaderValue(value: string): string {
  return value.replace(/(?:\r\n|\r|\n)[ \t]+/g, " ").trim();
}

function compactFoldedHeaderValue(value: string): string {
  return value.replace(/(?:\r\n|\r|\n)[ \t]+/g, "").trim();
}

function startsAuthorizationValue(value: string): boolean {
  const separator = value.search(/[ \t]/);
  if (separator <= 0 || !HTTP_TOKEN_PATTERN.test(value.slice(0, separator))) return false;
  const credential = value.slice(separator).trim();
  return AUTH_TOKEN68_PATTERN.test(credential) || AUTH_PARAMETER_PATTERN.test(credential);
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

function trailingFoldSeparator(value: string): FoldSeparator | undefined {
  const match = /([,;])[ \t]*$/.exec(value);
  return match?.[1] as FoldSeparator | undefined;
}

function authorizationTokenCanContinue(value: string, nextLine: string): boolean {
  if (
    !AUTH_TOKEN68_PATTERN.test(nextLine) &&
    !AUTH_TOKEN68_PADDING_PATTERN.test(nextLine)
  ) {
    return false;
  }
  const compacted = compactFoldedHeaderValue(value);
  if (HTTP_TOKEN_PATTERN.test(compacted)) return true;

  const separator = compacted.search(/[ \t]/);
  if (separator > 0 && HTTP_TOKEN_PATTERN.test(compacted.slice(0, separator))) {
    const credential = compacted.slice(separator).trim();
    if (AUTH_TOKEN68_PATTERN.test(credential)) return true;
  }

  return AUTH_PARAMETER_TAIL_PATTERN.test(compacted);
}

function isCookiePair(value: string): boolean {
  const separator = value.indexOf("=");
  if (separator <= 0 || !HTTP_TOKEN_PATTERN.test(value.slice(0, separator).trim())) return false;
  const cookieValue = value.slice(separator + 1).trim();
  if (!cookieValue) return false;
  if (cookieValue.startsWith('"')) return cookieValue.length >= 2 && cookieValue.endsWith('"');
  return COOKIE_VALUE_FRAGMENT_PATTERN.test(cookieValue);
}

function isCookiePairLine(headerName: SensitiveHeaderName, value: string): boolean {
  const segments = value.split(";");
  if (!isCookiePair(segments[0]!.trim())) return false;

  for (const segment of segments.slice(1)) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    if (headerName === "set-cookie") {
      if (!SET_COOKIE_ATTRIBUTE_PATTERN.test(trimmed)) return false;
    } else if (!isCookiePair(trimmed)) {
      return false;
    }
  }
  return true;
}

function cookieValueCanContinue(
  headerName: SensitiveHeaderName,
  value: string,
  nextLine: string,
): boolean {
  if (!COOKIE_VALUE_TAIL_PATTERN.test(compactFoldedHeaderValue(value))) return false;
  if (ASSIGNMENT_RECORD_PATTERN.test(nextLine)) return false;
  if (COOKIE_VALUE_FRAGMENT_PATTERN.test(nextLine)) return true;

  const delimiter = nextLine.indexOf(";");
  if (delimiter <= 0 || !COOKIE_VALUE_FRAGMENT_PATTERN.test(nextLine.slice(0, delimiter).trim())) {
    return false;
  }
  const remainder = nextLine.slice(delimiter + 1).trim();
  if (!remainder) return true;
  if (isCookiePairLine(headerName, remainder)) return true;
  return headerName === "set-cookie" && SET_COOKIE_ATTRIBUTE_PATTERN.test(remainder);
}

function separatedAuthorizationContinuation(value: string): boolean {
  return AUTH_PARAMETER_PATTERN.test(value);
}

function separatedCookieContinuation(
  headerName: SensitiveHeaderName,
  value: string,
): boolean {
  if (isCookiePairLine(headerName, value)) return true;
  return headerName === "set-cookie" && SET_COOKIE_ATTRIBUTE_PATTERN.test(value);
}

function isSyntacticContinuation(
  headerName: SensitiveHeaderName,
  headerValue: string,
  previousLine: string,
  nextLine: string,
): boolean {
  const trimmed = nextLine.trim();
  if (!trimmed || HEADER_LINE_PATTERN.test(trimmed)) return false;
  const unfolded = unfoldedHeaderValue(headerValue);
  const leadingSeparator = leadingFoldSeparator(trimmed);
  const previousSeparator = trailingFoldSeparator(previousLine);

  if (headerName === "authorization" || headerName === "proxy-authorization") {
    if (!unfolded) return startsAuthorizationValue(trimmed);
    if (leadingSeparator) {
      return separatedAuthorizationContinuation(leadingSeparator.remainder);
    }
    if (previousSeparator) return separatedAuthorizationContinuation(trimmed);
    if (ASSIGNMENT_RECORD_PATTERN.test(trimmed)) return false;
    return authorizationTokenCanContinue(headerValue, trimmed);
  }

  if (!unfolded) return isCookiePairLine(headerName, trimmed);
  if (leadingSeparator) {
    return separatedCookieContinuation(headerName, leadingSeparator.remainder);
  }
  if (previousSeparator) {
    return separatedCookieContinuation(headerName, trimmed);
  }
  if (ASSIGNMENT_RECORD_PATTERN.test(trimmed)) return false;
  return cookieValueCanContinue(headerName, headerValue, trimmed);
}

function continuationStart(
  value: string,
  lineBreakStart: number,
  headerValueStart: number,
  lineStart: number,
  headerName: SensitiveHeaderName,
): number | undefined {
  const nextLine = lineBreakEnd(value, lineBreakStart);
  if (value[nextLine] !== " " && value[nextLine] !== "\t") return undefined;
  const nextEnd = nextLineEnd(value, nextLine);
  return isSyntacticContinuation(
    headerName,
    value.slice(headerValueStart, lineBreakStart),
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
      const continuation = continuationStart(value, index, start, lineStart, headerName);
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
      const continuation = continuationStart(value, index, start, lineStart, headerName);
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
