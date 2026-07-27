import { types as utilTypes } from "node:util";

const SECRET_PATTERN =
  /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const CREDENTIAL_FIELD_PATTERN =
  /(^|[^A-Za-z0-9_. -])(["']?)([A-Za-z][A-Za-z0-9_. -]{0,63}?)\2[ \t]*[:=][ \t]*/gim;
const SERIALIZED_FIELD_PATTERN =
  /(^|[,{])([ \t]*)(("(?:\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4})|[^"\\\r\n])*")|('(?:\\(?:['"\\/bfnrt]|u[0-9A-Fa-f]{4})|[^'\\\r\n])*'))[ \t]*:[ \t]*/gm;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const EXPLICIT_DIAGNOSTIC_RECORD_PATTERN =
  /^(?:status|message|stack|detail)[ \t]*=/i;
const SENSITIVE_TERMINAL_TOKENS = new Set([
  "auth",
  "bearer",
  "credential",
  "passphrase",
  "password",
  "secret",
  "token",
]);
const SENSITIVE_EXACT_KEYS = new Set([
  "auth",
  "authheader",
  "authorization",
  "proxyauthorization",
  "cookie",
  "setcookie",
  "apikey",
  "privatekey",
  "clientsecret",
  "authtoken",
  "oauthtoken",
  "bearertoken",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "sessiontoken",
  "signingsecret",
  "consumersecret",
  "databasepassword",
  "webhookcredential",
  "xgoogapikey",
  "xamzsecuritytoken",
  "credential",
  "credentials",
  "password",
  "passphrase",
  "secret",
  "token",
]);
const SENSITIVE_TOKEN_STEMS = new Map([
  ["credentials", "credential"],
  ["passphrases", "passphrase"],
  ["passwords", "password"],
  ["secrets", "secret"],
  ["tokens", "token"],
]);

type FoldSeparator = "," | ";";

function semanticKeyTokens(value: string): string[] {
  return value
    .trim()
    .replace(/^--?/, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((token) => token.toLowerCase())
    .map((token) => SENSITIVE_TOKEN_STEMS.get(token) ?? token);
}

/**
 * Classify credential-bearing keys after separator and camel-case
 * normalization. Distinct `key` tokens are sensitive regardless of qualifier,
 * while token rules intentionally avoid substring matches such as `keyboard`,
 * `tokenBucket`, `passwordless`, `secretariat`, and `monkey`.
 */
export function isSensitiveCredentialKey(value: string): boolean {
  const tokens = semanticKeyTokens(value);
  if (tokens.length === 0) return false;

  const compact = tokens.join("");
  if (SENSITIVE_EXACT_KEYS.has(compact)) return true;
  if (tokens.includes("key")) return true;

  const terminal = tokens[tokens.length - 1]!;
  return SENSITIVE_TERMINAL_TOKENS.has(terminal);
}

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

function redactSensitiveFields(value: string): string {
  let cursor = 0;
  let output = "";
  CREDENTIAL_FIELD_PATTERN.lastIndex = 0;

  for (
    let match = CREDENTIAL_FIELD_PATTERN.exec(value);
    match;
    match = CREDENTIAL_FIELD_PATTERN.exec(value)
  ) {
    const valueStart = CREDENTIAL_FIELD_PATTERN.lastIndex;
    const keyStart =
      match.index +
      (match[1]?.length ?? 0) +
      (match[2]?.length ?? 0);
    const terminalFieldToken = match[3]!.trim().split(/[ \t]+/).at(-1) ?? "";
    if (
      value[keyStart - 1] === "-" ||
      normalizeCommandToken(terminalFieldToken).startsWith("-")
    ) {
      // Command-shaped options are handled by the quote-aware command scanner,
      // which can retain later options and diagnostics on the same line.
      CREDENTIAL_FIELD_PATTERN.lastIndex = valueStart;
      continue;
    }
    if (!isSensitiveCredentialKey(match[3]!)) {
      // A non-sensitive wrapper can contain a credential record in its value
      // (for example `message=Authorization: ...`). Resume just before the
      // value instead of skipping it with the wrapper match.
      CREDENTIAL_FIELD_PATTERN.lastIndex = Math.max(match.index + 1, valueStart - 1);
      continue;
    }
    const valueEnd = sensitiveRecordValueEnd(
      value,
      valueStart,
      isSerializedKey(value, match, valueStart),
    );
    if (valueEnd === valueStart) continue;
    output += value.slice(cursor, valueStart) + "[REDACTED]";
    cursor = valueEnd;
    CREDENTIAL_FIELD_PATTERN.lastIndex = valueEnd;
  }

  return cursor === 0 ? value : output + value.slice(cursor);
}

function redactEscapedSerializedFields(value: string): string {
  let cursor = 0;
  let output = "";
  SERIALIZED_FIELD_PATTERN.lastIndex = 0;

  for (
    let match = SERIALIZED_FIELD_PATTERN.exec(value);
    match;
    match = SERIALIZED_FIELD_PATTERN.exec(value)
  ) {
    const encodedKey = match[3]!;
    if (!encodedKey.includes("\\")) continue;

    const key = decodeSerializedKey(encodedKey);
    if (typeof key !== "string" || !isSensitiveCredentialKey(key)) continue;

    const valueStart = SERIALIZED_FIELD_PATTERN.lastIndex;
    const valueEnd = sensitiveRecordValueEnd(value, valueStart, true);
    if (valueEnd === valueStart) continue;
    output += value.slice(cursor, valueStart) + "[REDACTED]";
    cursor = valueEnd;
    SERIALIZED_FIELD_PATTERN.lastIndex = valueEnd;
  }

  return cursor === 0 ? value : output + value.slice(cursor);
}

function decodeSerializedKey(encoded: string): string | undefined {
  if (encoded[0] === '"') {
    try {
      const value = JSON.parse(encoded);
      return typeof value === "string" ? value : undefined;
    } catch {
      return undefined;
    }
  }
  if (encoded[0] !== "'" || encoded.at(-1) !== "'") return undefined;

  let output = "";
  for (let index = 1; index < encoded.length - 1; index++) {
    const char = encoded[index]!;
    if (char !== "\\") {
      output += char;
      continue;
    }
    const escaped = encoded[++index];
    if (!escaped) return undefined;
    if (escaped === "u") {
      const hex = encoded.slice(index + 1, index + 5);
      if (!/^[0-9A-Fa-f]{4}$/.test(hex)) return undefined;
      output += String.fromCharCode(Number.parseInt(hex, 16));
      index += 4;
      continue;
    }
    const escapes: Record<string, string> = {
      "'": "'",
      '"': '"',
      "\\": "\\",
      "/": "/",
      b: "\b",
      f: "\f",
      n: "\n",
      r: "\r",
      t: "\t",
    };
    const decoded = escapes[escaped];
    if (decoded === undefined) return undefined;
    output += decoded;
  }
  return output;
}

function redactPlainText(value: string): string {
  return redactSensitiveFields(
    redactEscapedSerializedFields(
      redactCommandText(value),
    ),
  ).replace(SECRET_PATTERN, "[REDACTED]");
}

function redactJsonDocument(value: string): { value: string; changed: boolean } {
  const leading = value.match(/^\s*/)?.[0] ?? "";
  const trailing = value.match(/\s*$/)?.[0] ?? "";
  const document = value.slice(leading.length, value.length - trailing.length);
  if (!document || (document[0] !== "{" && document[0] !== "[")) {
    return { value, changed: false };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch {
    return { value, changed: false };
  }

  let changed = false;
  const redacted = JSON.stringify(parsed, (key, nested) => {
    if (key && isSensitiveCredentialKey(key)) {
      changed = true;
      return "[REDACTED]";
    }
    if (typeof nested === "string") {
      const safe = redactPlainText(nested);
      if (safe !== nested) changed = true;
      return safe;
    }
    return nested;
  });
  return {
    value: changed ? `${leading}${redacted}${trailing}` : value,
    changed,
  };
}

type CredentialOption =
  | { kind: "attached"; redactedToken: string }
  | { kind: "separate"; redactedToken: string };

function normalizeCommandToken(value: string): string {
  return value
    .normalize("NFKC")
    .replace(/^[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]+/, (dashes) =>
      "-".repeat(dashes.length),
    );
}

function credentialOption(
  value: string,
  requireOptionPrefix = false,
): CredentialOption | undefined {
  const normalized = normalizeCommandToken(value);
  if (requireOptionPrefix && !normalized.startsWith("-")) return undefined;

  const separator = normalized.search(/[=:]/);
  if (
    separator > 0 &&
    isSensitiveCredentialKey(normalized.slice(0, separator))
  ) {
    return {
      kind: "attached",
      redactedToken: `${normalized.slice(0, separator + 1)}[REDACTED]`,
    };
  }

  const shortOption = /^-(?!-)(.*)$/.exec(normalized)?.[1];
  const shortCredentialIndex = shortOption?.toLowerCase().indexOf("k") ?? -1;
  if (
    shortOption &&
    shortCredentialIndex >= 0 &&
    /^[A-Za-z]+$/.test(shortOption.slice(0, shortCredentialIndex + 1))
  ) {
    return shortCredentialIndex === shortOption.length - 1
      ? { kind: "separate", redactedToken: normalized }
      : {
          kind: "attached",
          redactedToken: `-${shortOption.slice(0, shortCredentialIndex + 1)}[REDACTED]`,
        };
  }

  return isSensitiveCredentialKey(normalized)
    ? { kind: "separate", redactedToken: normalized }
    : undefined;
}

interface CommandOptionView {
  prefix: string;
  suffix: string;
  option?: CredentialOption;
  endOfOptions: boolean;
}

const EMBEDDED_OPTION_BOUNDARIES = new Set([
  ":",
  "=",
  "|",
  "/",
  "<",
  ">",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  ",",
  ";",
]);
const EMBEDDED_OPTION_TERMINATORS = new Set([
  ")",
  "]",
  "}",
  ">",
  ",",
  ";",
]);

interface CommandSegmentContext {
  length: number;
  hasAt: boolean;
  isUrl: boolean;
  startsWithWww: boolean;
  schemeCandidate: boolean;
  mailtoCandidate: boolean;
  wwwCandidate: boolean;
  outerClosures: string[];
  structuredClosures: string[];
}

const COMMAND_SEGMENT_RESTART_BOUNDARIES = new Set([
  "=",
  ":",
  "|",
  ",",
  ";",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  "<",
  ">",
]);
const COMMAND_WRAPPER_CLOSURES = new Map([
  ["(", ")"],
  ["[", "]"],
  ["{", "}"],
  ["<", ">"],
]);

function commandSegmentContext(): CommandSegmentContext {
  return {
    length: 0,
    hasAt: false,
    isUrl: false,
    startsWithWww: false,
    schemeCandidate: true,
    mailtoCandidate: true,
    wwwCandidate: true,
    outerClosures: [],
    structuredClosures: [],
  };
}

function resetCommandSegmentContext(context: CommandSegmentContext): void {
  context.length = 0;
  context.hasAt = false;
  context.isUrl = false;
  context.startsWithWww = false;
  context.schemeCandidate = true;
  context.mailtoCandidate = true;
  context.wwwCandidate = true;
}

function clearCommandSegmentContext(context: CommandSegmentContext): void {
  resetCommandSegmentContext(context);
  context.outerClosures.length = 0;
  context.structuredClosures.length = 0;
}

function observeCommandSegmentChar(
  context: CommandSegmentContext,
  char: string,
  next = "",
  afterNext = "",
): void {
  if (
    char === " " ||
    char === "\t" ||
    char === "\r" ||
    char === "\n"
  ) {
    clearCommandSegmentContext(context);
    return;
  }

  const wasStructured = isStructuredCommandSegment(context);
  const wrapperClosure = COMMAND_WRAPPER_CLOSURES.get(char);
  if (wrapperClosure) {
    (
      wasStructured
        ? context.structuredClosures
        : context.outerClosures
    ).push(wrapperClosure);
  }

  const position = context.length;
  if (char === "@") context.hasAt = true;
  if (
    char === ":" &&
    context.schemeCandidate &&
    position > 0 &&
    (
      (next === "/" && afterNext === "/") ||
      (context.mailtoCandidate && position === "mailto".length)
    )
  ) {
    context.isUrl = true;
  }

  if (position === 0) {
    context.schemeCandidate = /[A-Za-z]/.test(char);
  } else if (context.schemeCandidate && !/[A-Za-z0-9+.-]/.test(char)) {
    context.schemeCandidate = false;
  }
  if (
    position >= "mailto".length ||
    char.toLowerCase() !== "mailto"[position]
  ) {
    context.mailtoCandidate = false;
  }
  if (position >= "www.".length || char.toLowerCase() !== "www."[position]) {
    context.wwwCandidate = false;
  }
  context.length++;
  if (context.wwwCandidate && context.length === "www.".length) {
    context.startsWithWww = true;
  }

  let closedOuterWrapper = false;
  if (
    context.structuredClosures.at(-1) === char
  ) {
    context.structuredClosures.pop();
  } else if (context.outerClosures.at(-1) === char) {
    context.outerClosures.pop();
    context.structuredClosures.length = 0;
    closedOuterWrapper = true;
  }
  if (
    closedOuterWrapper ||
    (
      COMMAND_SEGMENT_RESTART_BOUNDARIES.has(char) &&
      !isStructuredCommandSegment(context)
    )
  ) {
    resetCommandSegmentContext(context);
  }
}

function isStructuredCommandSegment(context: CommandSegmentContext): boolean {
  return context.hasAt || context.isUrl || context.startsWithWww;
}

function isArithmeticOptionBoundary(value: string, start: number): boolean {
  const previous = value[start - 1];
  if (previous !== "/" && previous !== "<" && previous !== ">") {
    return false;
  }

  let cursor = start - 2;
  while (
    cursor >= 0 &&
    (
      value[cursor] === " " ||
      value[cursor] === "\t" ||
      value[cursor] === ")" ||
      value[cursor] === "]" ||
      value[cursor] === "}"
    )
  ) {
    cursor--;
  }
  return /[0-9]/.test(value[cursor] ?? "");
}

function commandOptionView(
  value: string,
  includeNonSensitive = false,
  protectArithmetic = true,
): CommandOptionView | undefined {
  const segment = commandSegmentContext();

  for (let start = 0; start < value.length;) {
    const previous = value[start - 1];
    const structuredBoundary =
      start !== 0 &&
      isStructuredCommandSegment(segment);
    const boundary =
      start === 0 ||
      (
        EMBEDDED_OPTION_BOUNDARIES.has(previous!) &&
        (!protectArithmetic || !isArithmeticOptionBoundary(value, start)) &&
        !structuredBoundary
      );
    if (
      !boundary ||
      !normalizeCommandToken(value[start]!).startsWith("-")
    ) {
      observeCommandSegmentChar(
        segment,
        value[start]!,
        value[start + 1],
        value[start + 2],
      );
      start++;
      continue;
    }

    let end = start;
    while (end < value.length) {
      const char = value[end]!;
      if (EMBEDDED_OPTION_TERMINATORS.has(char)) break;
      if (
        end > start &&
        EMBEDDED_OPTION_BOUNDARIES.has(char) &&
        normalizeCommandToken(value[end + 1] ?? "").startsWith("-")
      ) {
        const possibleAttachedKey = normalizeCommandToken(
          value.slice(start, end),
        );
        if (
          (char === "=" || char === ":") &&
          isSensitiveCredentialKey(possibleAttachedKey)
        ) {
          end++;
          continue;
        }
        break;
      }
      end++;
    }
    const token = value.slice(start, end);
    const normalized = normalizeCommandToken(token);
    if (normalized === "--") {
      return {
        prefix: value.slice(0, start),
        suffix: value.slice(end),
        endOfOptions: true,
      };
    }

    const separator = normalized.search(/[=:]/);
    let option: CredentialOption | undefined;
    if (
      separator > 0 &&
      isSensitiveCredentialKey(normalized.slice(0, separator))
    ) {
      option = {
        kind: "attached",
        redactedToken: `${normalized.slice(0, separator + 1)}[REDACTED]`,
      };
    } else if (!normalized.startsWith("--")) {
      option = credentialOption(token, true);
    } else if (separator < 0) {
      option = credentialOption(token, true);
    }
    if (option) {
      return {
        prefix: value.slice(0, start),
        suffix: value.slice(end),
        option,
        endOfOptions: false,
      };
    }
    if (includeNonSensitive) {
      return {
        prefix: value.slice(0, start),
        suffix: value.slice(end),
        endOfOptions: false,
      };
    }
    while (start < end) {
      observeCommandSegmentChar(
        segment,
        value[start]!,
        value[start + 1],
        value[start + 2],
      );
      start++;
    }
  }
  return undefined;
}

interface CommandToken {
  start: number;
  end: number;
  decoded: string;
  quoted: boolean;
  escaped: boolean;
  openQuote?: "'" | '"';
  trailingEscape: boolean;
}

function scanCommandToken(
  value: string,
  start: number,
  lineEnd: number,
  protectArithmetic = true,
): CommandToken {
  let decoded = "";
  let quote: "'" | '"' | undefined;
  let index = start;
  let quoted = false;
  let escaped = false;
  let optionDecodedStart = normalizeCommandToken(value[start] ?? "").startsWith("-")
    ? 0
    : undefined;
  let sensitiveAttachedSeen = false;
  const segment = commandSegmentContext();

  while (index < lineEnd) {
    const char = value[index]!;
    if (!quote && (char === " " || char === "\t")) break;
    const startsEmbeddedOption =
      !quote &&
      EMBEDDED_OPTION_BOUNDARIES.has(char) &&
      normalizeCommandToken(value[index + 1] ?? "").startsWith("-") &&
      !isStructuredCommandSegment(segment);
    if (
      startsEmbeddedOption &&
      index > start &&
      (
        !protectArithmetic ||
        sensitiveAttachedSeen ||
        !isArithmeticOptionBoundary(value, index + 1)
      )
    ) {
      break;
    }
    const optionStartsAfterBoundary = startsEmbeddedOption && index === start;
    if (char === "\\") {
      escaped = true;
      if (index + 1 < lineEnd) {
        const escapedChar = value[index + 1]!;
        quoted ||= escapedChar === "'" || escapedChar === '"';
        if (escapedChar === "'" || escapedChar === '"') {
          if (!quote) {
            quote = escapedChar;
            index += 2;
            continue;
          }
          if (quote === escapedChar) {
            quote = undefined;
            segment.structuredClosures.length = 0;
            resetCommandSegmentContext(segment);
            index += 2;
            continue;
          }
        }
        decoded += escapedChar;
        observeCommandSegmentChar(
          segment,
          escapedChar,
          value[index + 2],
          value[index + 3],
        );
        index += 2;
        continue;
      }
      decoded += char;
      observeCommandSegmentChar(segment, char);
      index++;
      continue;
    }
    if (char === "'" || char === '"') {
      quoted = true;
      if (!quote) {
        quote = char;
        index++;
        continue;
      }
      if (quote === char) {
        quote = undefined;
        segment.structuredClosures.length = 0;
        resetCommandSegmentContext(segment);
        index++;
        continue;
      }
    }
    if (
      !quote &&
      optionDecodedStart !== undefined &&
      (char === "=" || char === ":") &&
      credentialOption(
          `${decoded.slice(optionDecodedStart)}${char}`,
          true,
        )?.kind === "attached"
    ) {
      sensitiveAttachedSeen = true;
    }
    decoded += char;
    observeCommandSegmentChar(
      segment,
      char,
      value[index + 1],
      value[index + 2],
    );
    if (optionStartsAfterBoundary) optionDecodedStart = decoded.length;
    index++;
  }

  let trailingBackslashes = 0;
  for (
    let cursor = index - 1;
    cursor >= start && value[cursor] === "\\";
    cursor--
  ) {
    trailingBackslashes++;
  }
  return {
    start,
    end: index,
    decoded,
    quoted,
    escaped,
    openQuote: quote,
    trailingEscape: trailingBackslashes % 2 === 1,
  };
}

function isExplicitCommandRecordBoundary(
  value: string,
  lineStart: number,
  lineEnd: number,
): boolean {
  const line = value.slice(lineStart, lineEnd).trim();
  return EXPLICIT_DIAGNOSTIC_RECORD_PATTERN.test(line);
}

function findUnescapedQuote(
  value: string,
  start: number,
  end: number,
  quote: "'" | '"',
): number | undefined {
  let backslashes = 0;
  for (let index = start; index < end; index++) {
    const char = value[index]!;
    if (char === "\\") {
      backslashes++;
      continue;
    }
    if (char === quote && backslashes % 2 === 0) return index;
    backslashes = 0;
  }
  return undefined;
}

function isEscapedAt(value: string, index: number): boolean {
  let backslashes = 0;
  for (
    let cursor = index - 1;
    cursor >= 0 && value[cursor] === "\\";
    cursor--
  ) {
    backslashes++;
  }
  return backslashes % 2 === 1;
}

function isInsideCommandQuote(value: string, index: number): boolean {
  let quote: "'" | '"' | undefined;
  for (let cursor = 0; cursor < index; cursor++) {
    const char = value[cursor]!;
    if (char === "\\") {
      cursor++;
      continue;
    }
    if (char !== "'" && char !== '"') continue;
    if (!quote) quote = char;
    else if (quote === char) quote = undefined;
  }
  return quote !== undefined;
}

function hasSubstantiveCommandValue(value: string): boolean {
  return /[^\s'"\\()[\]{}<>:;=|/,]/u.test(value);
}

function commandValueOptionSplit(
  token: CommandToken,
  raw: string,
): { valueEnd: number; optionStart: number } | undefined {
  const view = commandOptionView(token.decoded, true, false);
  if (!view) return undefined;
  const candidateEnd = token.decoded.length - view.suffix.length;
  const candidate = token.decoded.slice(view.prefix.length, candidateEnd);
  if (!candidate) return undefined;

  const optionOffset = raw.lastIndexOf(candidate);
  if (optionOffset <= 0) return undefined;
  const boundaryOffset = optionOffset - 1;
  if (
    !EMBEDDED_OPTION_BOUNDARIES.has(raw[boundaryOffset]!) ||
    isEscapedAt(raw, boundaryOffset) ||
    isInsideCommandQuote(raw, boundaryOffset) ||
    !hasSubstantiveCommandValue(raw.slice(0, boundaryOffset))
  ) {
    return undefined;
  }
  return {
    valueEnd: token.start + boundaryOffset,
    optionStart: token.start + optionOffset,
  };
}

function outerQuotedParts(
  raw: string,
): { quote: "'" | '"'; suffix: string } | undefined {
  const quote = raw[0];
  if (quote !== "'" && quote !== '"') return undefined;
  for (let index = 1; index < raw.length; index++) {
    if (raw[index] === "\\") {
      index++;
      continue;
    }
    if (raw[index] === quote) {
      return { quote, suffix: raw.slice(index + 1) };
    }
  }
  return undefined;
}

function replaceCommandToken(
  raw: string,
  redactedToken: string,
): string {
  const outer = outerQuotedParts(raw);
  return outer
    ? `${outer.quote}${redactedToken}${outer.quote}${outer.suffix}`
    : redactedToken;
}

function replaceCommandValue(raw: string, syntaxProtected = false): string {
  const outer = outerQuotedParts(raw);
  if (syntaxProtected && outer?.suffix) return "[REDACTED]";
  if (syntaxProtected && !outer) return "[REDACTED]";
  return outer
    ? `${outer.quote}[REDACTED]${outer.quote}${outer.suffix}`
    : "[REDACTED]";
}

/**
 * Redact credential options embedded in captured command output. The scanner
 * is single-pass and shares option classification with `redactArgv`. A
 * pending separate value crosses one or more physical line endings until the
 * next syntactic token, but a blank line or an explicit status/message/stack/
 * detail record terminates that command record. Quoted or escaped tokens
 * remain bound values even when their decoded text resembles another option.
 * Open quotes and odd trailing backslashes keep that logical value redacted
 * across later physical fragments.
 */
function redactCommandTokens(value: string): string {
  const parts: string[] = [];
  let outputCursor = 0;
  let lineStart = 0;
  let redactNext = false;
  let pendingCrossedLine = false;
  let endOfOptions = false;
  let valueContinuation:
    | {
        quote?: "'" | '"';
        escaped: boolean;
        crossedLine: boolean;
      }
    | undefined;

  while (lineStart < value.length) {
    const lineEnd = physicalLineEnd(value, lineStart);
    const blankLine = value.slice(lineStart, lineEnd).trim().length === 0;
    const explicitRecord = isExplicitCommandRecordBoundary(
      value,
      lineStart,
      lineEnd,
    );
    if (
      redactNext &&
      pendingCrossedLine &&
      (blankLine || explicitRecord)
    ) {
      redactNext = false;
      pendingCrossedLine = false;
    }
    if (
      valueContinuation?.crossedLine &&
      (blankLine || explicitRecord)
    ) {
      valueContinuation = undefined;
    }

    let tokenCursor = lineStart;
    if (valueContinuation) {
      while (
        tokenCursor < lineEnd &&
        (value[tokenCursor] === " " || value[tokenCursor] === "\t")
      ) {
        tokenCursor++;
      }
      if (tokenCursor < lineEnd && valueContinuation.quote) {
        const close = findUnescapedQuote(
          value,
          tokenCursor,
          lineEnd,
          valueContinuation.quote,
        );
        const continuationEnd = close === undefined ? lineEnd : close + 1;
        parts.push(
          value.slice(outputCursor, tokenCursor),
          "[REDACTED]",
        );
        outputCursor = continuationEnd;
        if (close === undefined) {
          tokenCursor = lineEnd;
        } else {
          valueContinuation = undefined;
          tokenCursor = continuationEnd;
        }
      } else if (tokenCursor < lineEnd) {
        const token = scanCommandToken(value, tokenCursor, lineEnd, false);
        const raw = value.slice(token.start, token.end);
        const split = commandValueOptionSplit(token, raw);
        const redactionEnd = split?.valueEnd ?? token.end;
        parts.push(
          value.slice(outputCursor, token.start),
          "[REDACTED]",
        );
        outputCursor = redactionEnd;
        valueContinuation = !split && token.trailingEscape
          ? { escaped: true, crossedLine: false }
          : undefined;
        tokenCursor = split?.optionStart ?? token.end;
      }
    }

    while (tokenCursor < lineEnd) {
      while (
        tokenCursor < lineEnd &&
        (value[tokenCursor] === " " || value[tokenCursor] === "\t")
      ) {
        tokenCursor++;
      }
      if (tokenCursor >= lineEnd) break;

      const item = scanCommandToken(
        value,
        tokenCursor,
        lineEnd,
        !redactNext,
      );
      const raw = value.slice(item.start, item.end);
      const optionView = !endOfOptions
        ? commandOptionView(item.decoded)
        : undefined;
      const nextOptionView =
        redactNext
          ? commandOptionView(item.decoded, true)
          : undefined;

      if (redactNext) {
        const bareLineContinuation =
          !item.quoted &&
          item.trailingEscape &&
          item.decoded === "\\";
        if (bareLineContinuation) {
          pendingCrossedLine = false;
          tokenCursor = item.end;
          continue;
        }
        const split = commandValueOptionSplit(item, raw);
        if (split) {
          parts.push(
            value.slice(outputCursor, item.start),
            replaceCommandValue(
              value.slice(item.start, split.valueEnd),
              item.quoted || item.escaped,
            ),
          );
          outputCursor = split.valueEnd;
          redactNext = false;
          pendingCrossedLine = false;
          tokenCursor = split.optionStart;
          continue;
        }
        if (
          !item.quoted &&
          !item.escaped &&
          (nextOptionView || normalizeCommandToken(item.decoded).startsWith("-"))
        ) {
          redactNext = false;
        } else {
          parts.push(
            value.slice(outputCursor, item.start),
            replaceCommandValue(raw, item.quoted || item.escaped),
          );
          outputCursor = item.end;
          redactNext = false;
          pendingCrossedLine = false;
          if (item.openQuote || item.trailingEscape) {
            valueContinuation = {
              quote: item.openQuote,
              escaped: item.openQuote === undefined && item.trailingEscape,
              crossedLine: false,
            };
          }
          tokenCursor = item.end;
          continue;
        }
      }

      pendingCrossedLine = false;
      if (!endOfOptions && optionView?.endOfOptions) {
        endOfOptions = true;
      } else if (optionView?.option) {
        if (optionView.option.kind === "attached") {
          const suffixStart =
            optionView.suffix &&
            raw.endsWith(optionView.suffix) &&
            !isEscapedAt(raw, raw.length - optionView.suffix.length) &&
            !isInsideCommandQuote(
              raw,
              raw.length - optionView.suffix.length,
            )
              ? item.end - optionView.suffix.length
              : undefined;
          const optionRaw = suffixStart === undefined
            ? raw
            : value.slice(item.start, suffixStart);
          const retainedSuffix = /['"\\]/.test(raw)
            ? ""
            : optionView.suffix;
          parts.push(
            value.slice(outputCursor, item.start),
            replaceCommandToken(
              optionRaw,
              `${optionView.prefix}${optionView.option.redactedToken}${
                suffixStart === undefined ? retainedSuffix : ""
              }`,
            ),
          );
          outputCursor = suffixStart ?? item.end;
          if (item.openQuote || item.trailingEscape) {
            valueContinuation = {
              quote: item.openQuote,
              escaped: item.openQuote === undefined && item.trailingEscape,
              crossedLine: false,
            };
          }
          if (suffixStart !== undefined) {
            tokenCursor = suffixStart;
            continue;
          }
        } else {
          redactNext = true;
        }
      }
      tokenCursor = item.end;
    }

    if (lineEnd >= value.length) break;
    endOfOptions = false;
    if (redactNext) pendingCrossedLine = true;
    if (valueContinuation) valueContinuation.crossedLine = true;
    lineStart = lineBreakEnd(value, lineEnd);
    if (lineStart >= value.length) break;
  }

  if (outputCursor === 0) return value;
  parts.push(value.slice(outputCursor));
  return parts.join("");
}

function redactQuotedCommandSegments(value: string): string {
  const parts: string[] = [];
  let cursor = 0;
  let lineStart = 0;

  while (lineStart < value.length) {
    const lineEnd = physicalLineEnd(value, lineStart);
    let index = lineStart;
    while (index < lineEnd) {
      const quote = value[index];
      if (quote !== "'" && quote !== '"') {
        index++;
        continue;
      }

      let close = index + 1;
      while (close < lineEnd) {
        if (value[close] === "\\") {
          close += 2;
          continue;
        }
        if (value[close] === quote) break;
        close++;
      }
      if (close >= lineEnd) {
        index++;
        continue;
      }

      const inner = value.slice(index + 1, close);
      const redacted = redactCommandTokens(inner);
      if (redacted !== inner) {
        parts.push(
          value.slice(cursor, index + 1),
          redacted,
        );
        cursor = close;
      }
      index = close + 1;
    }
    lineStart = lineEnd < value.length
      ? lineBreakEnd(value, lineEnd)
      : value.length;
  }

  if (cursor === 0) return value;
  parts.push(value.slice(cursor));
  return parts.join("");
}

function redactCommandText(value: string): string {
  return redactQuotedCommandSegments(redactCommandTokens(value));
}

/** Redact values that follow credential-bearing command-line flags. */
export function redactArgv(argv: string[]): string[] {
  const redacted: string[] = [];
  let redactNext = false;
  for (const arg of argv) {
    if (redactNext) {
      redacted.push("[REDACTED]");
      redactNext = false;
      continue;
    }

    const option = credentialOption(arg);
    if (option?.kind === "attached") {
      redacted.push(option.redactedToken);
      continue;
    }
    if (option?.kind === "separate") {
      redacted.push(option.redactedToken);
      redactNext = true;
      continue;
    }
    redacted.push(redactText(arg));
  }
  return redacted;
}

const POLLUTION_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function publicValue(
  value: unknown,
  seen: WeakSet<object>,
): unknown {
  if (typeof value === "string") return redactText(value);
  if (
    value === null ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (typeof value !== "object") return null;
  if (utilTypes.isProxy(value) || seen.has(value)) return null;

  const isArray = Array.isArray(value);
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value);
    if (
      (!isArray && prototype !== Object.prototype && prototype !== null) ||
      (isArray && prototype !== Array.prototype)
    ) {
      return null;
    }
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }

  seen.add(value);
  if (isArray) {
    const length = descriptors["length"]?.value;
    if (
      typeof length !== "number" ||
      !Number.isSafeInteger(length) ||
      length < 0
    ) {
      return null;
    }
    const result: unknown[] = [];
    result.length = length;
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]!;
      const numeric = Number(key);
      if (
        !descriptor.enumerable ||
        !("value" in descriptor) ||
        !Number.isSafeInteger(numeric) ||
        numeric < 0 ||
        String(numeric) !== key ||
        numeric >= length
      ) {
        continue;
      }
      result[numeric] = publicValue(descriptor.value, seen);
    }
    return result;
  }

  const result: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key]!;
    if (
      POLLUTION_KEYS.has(key) ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      continue;
    }
    result[key] = isSensitiveCredentialKey(key)
      ? "[REDACTED]"
      : publicValue(descriptor.value, seen);
  }
  return result;
}

/** Redact credential-bearing keys and nested string diagnostics in public data. */
export function redactPublicValue(value: unknown): unknown {
  return publicValue(value, new WeakSet());
}

/** Redact environment values by both semantic key and embedded diagnostic form. */
export function redactEnvironment(env: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).map(([key, value]) => [
      key,
      isSensitiveCredentialKey(key) ? "[REDACTED]" : redactText(value),
    ]),
  );
}

/** Redact common credential values and credential-bearing request headers. */
export function redactText(value: string): string {
  const json = redactJsonDocument(value);
  return json.changed ? json.value : redactPlainText(value);
}
