const SECRET_PATTERN =
  /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SENSITIVE_REQUEST_HEADER_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(authorization|proxy-authorization|cookie|set-cookie)\2[ \t]*[:=][ \t]*/gim;
const SENSITIVE_CREDENTIAL_FIELD_PATTERN =
  /(^|[^A-Za-z0-9_-])(["']?)(x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\2[ \t]*[:=][ \t]*/gim;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const EXPLICIT_DIAGNOSTIC_RECORD_PATTERN =
  /^(?:status|message|stack|detail)[ \t]*=[ \t]*\S/i;

type FoldSeparator = "," | ";";

function lineBreakEnd(value: string, start: number): number {
  return value[start] === "\r" && value[start + 1] === "\n" ? start + 2 : start + 1;
}

function physicalLineEnd(value: string, start: number): number {
  let index = start;
  while (index < value.length && value[index] !== "\r" && value[index] !== "\n") {
    index++;
  }
  return index;
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

function isSerializedKey(
  value: string,
  match: RegExpExecArray,
  valueStart: number,
): boolean {
  if (!match[2]) return false;

  let delimiter = valueStart - 1;
  while (delimiter >= 0 && (value[delimiter] === " " || value[delimiter] === "\t")) {
    delimiter--;
  }
  if (value[delimiter] !== ":") return false;

  const keyStart = match.index + (match[1]?.length ?? 0);
  let previous = keyStart - 1;
  while (previous >= 0 && (value[previous] === " " || value[previous] === "\t")) {
    previous--;
  }
  return (
    value[previous] === "{" ||
    value[previous] === ","
  );
}

function isSerializedSiblingBoundary(value: string, start: number): boolean {
  let index = start;
  while (value[index] === " " || value[index] === "\t") index++;

  if (index >= value.length || value[index] === "}") {
    return true;
  }
  if (value[index] !== ",") return false;
  index++;
  while (value[index] === " " || value[index] === "\t") index++;

  const quote = value[index];
  if (quote !== '"' && quote !== "'") return false;
  index++;
  while (index < value.length) {
    const char = value[index]!;
    if (char === "\r" || char === "\n") return false;
    if (char === "\\") {
      index += 2;
      continue;
    }
    if (char === quote) break;
    index++;
  }
  if (value[index] !== quote) return false;
  index++;
  while (value[index] === " " || value[index] === "\t") index++;
  return value[index] === ":";
}

function isSyntacticContinuation(
  sawContent: boolean,
  lastSignificant: string | undefined,
  forceContinuation: boolean,
  nextLine: string,
): boolean {
  const trimmed = nextLine.trim();
  if (!trimmed || forceContinuation || !sawContent) return true;

  const leadingSeparator = leadingFoldSeparator(trimmed);
  if (leadingSeparator || lastSignificant === "," || lastSignificant === ";") {
    return true;
  }

  if (HEADER_LINE_PATTERN.test(trimmed)) return false;
  return !EXPLICIT_DIAGNOSTIC_RECORD_PATTERN.test(trimmed);
}

function sensitiveRecordValueEnd(
  value: string,
  start: number,
  serializedKey: boolean,
): number {
  const wrapperQuote =
    value[start] === '"' || value[start] === "'" ? value[start] : undefined;
  let quote = wrapperQuote;
  let sawContent = false;
  let lastSignificant: string | undefined;
  let forceContinuation = false;

  for (let index = start + (wrapperQuote ? 1 : 0); index < value.length; index++) {
    const char = value[index]!;

    if (char === "\r" || char === "\n") {
      const nextLine = lineBreakEnd(value, index);
      if (value[nextLine] !== " " && value[nextLine] !== "\t") return index;

      const nextEnd = physicalLineEnd(value, nextLine);
      const nextText = value.slice(nextLine, nextEnd);
      if (
        !quote &&
        !isSyntacticContinuation(
          sawContent,
          lastSignificant,
          forceContinuation,
          nextText,
        )
      ) {
        return index;
      }

      const trimmed = nextText.trim();
      const separator = leadingFoldSeparator(trimmed);
      forceContinuation = !trimmed || Boolean(separator && !separator.remainder);
      index = nextLine - 1;
      continue;
    }

    if (quote) {
      if (char === "\\") {
        if (index + 1 < value.length) index++;
        continue;
      }
      if (char === quote) {
        if (
          wrapperQuote &&
          serializedKey &&
          isSerializedSiblingBoundary(value, index + 1)
        ) {
          return index + 1;
        }
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

function redactSensitiveFields(value: string, pattern: RegExp): string {
  let cursor = 0;
  let output = "";
  pattern.lastIndex = 0;

  for (
    let match = pattern.exec(value);
    match;
    match = pattern.exec(value)
  ) {
    const valueStart = pattern.lastIndex;
    const valueEnd = sensitiveRecordValueEnd(
      value,
      valueStart,
      isSerializedKey(value, match, valueStart),
    );
    if (valueEnd === valueStart) continue;
    output += value.slice(cursor, valueStart) + "[REDACTED]";
    cursor = valueEnd;
    pattern.lastIndex = valueEnd;
  }

  return cursor === 0 ? value : output + value.slice(cursor);
}

/** Redact common credential values and credential-bearing request headers. */
export function redactText(value: string): string {
  return redactSensitiveFields(
    redactSensitiveFields(value, SENSITIVE_REQUEST_HEADER_PATTERN),
    SENSITIVE_CREDENTIAL_FIELD_PATTERN,
  ).replace(SECRET_PATTERN, "[REDACTED]");
}
