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
  const structuredContext = commandSegmentContext();
  let structuredCursor = 0;
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
    while (structuredCursor < keyStart) {
      observeCommandSegmentChar(
        structuredContext,
        value[structuredCursor]!,
        value[structuredCursor + 1],
        value[structuredCursor + 2],
      );
      structuredCursor++;
    }
    const terminalFieldToken = match[3]!.trim().split(/[ \t]+/).at(-1) ?? "";
    if (
      value[keyStart - 1] === "-" ||
      normalizeCommandToken(terminalFieldToken).startsWith("-") ||
      /(^|[ \t])--(?=[ \t]|$)/.test(match[3]!)
    ) {
      // Command-shaped options are handled by the quote-aware command scanner,
      // which can retain later options and diagnostics on the same line.
      CREDENTIAL_FIELD_PATTERN.lastIndex = valueStart;
      continue;
    }
    if (isStructuredCommandSegment(structuredContext)) {
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

function isBareCommandOption(value: string): boolean {
  return /^--?[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value);
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
    (
      !requireOptionPrefix ||
      isBareCommandOption(normalized.slice(0, separator))
    ) &&
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

  if (
    requireOptionPrefix &&
    !isBareCommandOption(normalized)
  ) {
    return undefined;
  }
  return isSensitiveCredentialKey(normalized)
    ? { kind: "separate", redactedToken: normalized }
    : undefined;
}

interface CommandOptionView {
  prefix: string;
  suffix: string;
  option?: CredentialOption;
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
  urnCandidate: boolean;
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
    urnCandidate: true,
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
  context.urnCandidate = true;
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
      (context.mailtoCandidate && position === "mailto".length) ||
      (context.urnCandidate && position === "urn".length) ||
      (position === 1 && (next === "/" || next === "\\"))
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
  if (
    position >= "urn".length ||
    char.toLowerCase() !== "urn"[position]
  ) {
    context.urnCandidate = false;
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
      // End-of-options is control syntax, not normalized option grammar.
      // Embedded discovery must never promote a compatibility-normalized,
      // wrapped, or punctuation-adjacent dash pair into that control state.
      while (start < end) {
        observeCommandSegmentChar(
          segment,
          value[start]!,
          value[start + 1],
          value[start + 2],
        );
        start++;
      }
      continue;
    }

    const separator = normalized.search(/[=:]/);
    let option: CredentialOption | undefined;
    if (
      separator > 0 &&
      (
        !includeNonSensitive ||
        isBareCommandOption(normalized.slice(0, separator))
      ) &&
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
      };
    }
    if (includeNonSensitive) {
      return {
        prefix: value.slice(0, start),
        suffix: value.slice(end),
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
  openQuoteStart?: number;
  openQuoteEscaped: boolean;
  trailingEscape: boolean;
}

const MAX_UNTERMINATED_COMMAND_QUOTE_RECOVERIES = 8;

function completeCommandOptionView(
  token: CommandToken,
): CommandOptionView | undefined {
  if (token.quoted || token.escaped) return undefined;

  const view = commandOptionView(token.decoded, true);
  if (!view || view.prefix || view.suffix) return undefined;
  const normalized = normalizeCommandToken(token.decoded);

  if (isBareCommandOption(normalized)) return view;
  return view.option?.kind === "attached" ? view : undefined;
}

function isExactCommandEndOfOptions(
  token: CommandToken,
  raw: string,
): boolean {
  return (
    raw === "--" &&
    token.decoded === "--" &&
    !token.quoted &&
    !token.escaped &&
    token.openQuote === undefined &&
    !token.trailingEscape
  );
}

function scanCommandToken(
  value: string,
  start: number,
  lineEnd: number,
  protectArithmetic = true,
  splitEmbeddedOptions = true,
  escapedQuotesOpen = true,
): CommandToken {
  let decoded = "";
  let quote: "'" | '"' | undefined;
  let index = start;
  let quoted = false;
  let escaped = false;
  let quoteStart: number | undefined;
  let quoteOpenedEscaped = false;
  let optionDecodedStart = normalizeCommandToken(value[start] ?? "").startsWith("-")
    ? 0
    : undefined;
  let optionSeparatorSeen = false;
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
    const isOptionSeparator =
      !quote &&
      optionDecodedStart !== undefined &&
      (char === "=" || char === ":");
    const startsSensitiveAttachedValue =
      isOptionSeparator &&
      !optionSeparatorSeen &&
      credentialOption(
          `${decoded.slice(optionDecodedStart)}${char}`,
          true,
        )?.kind === "attached";
    if (
      splitEmbeddedOptions &&
      startsEmbeddedOption &&
      index > start &&
      !startsSensitiveAttachedValue &&
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
          const escapedQuoteStartsSensitiveValue =
            !quote && credentialOption(decoded, true) !== undefined;
          if (!escapedQuotesOpen && !escapedQuoteStartsSensitiveValue) {
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
          if (!quote) {
            quote = escapedChar;
            quoteStart = index + 1;
            quoteOpenedEscaped = true;
            index += 2;
            continue;
          }
          if (quote === escapedChar) {
            quote = undefined;
            quoteStart = undefined;
            quoteOpenedEscaped = false;
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
        quoteStart = index;
        quoteOpenedEscaped = false;
        index++;
        continue;
      }
      if (quote === char) {
        quote = undefined;
        quoteStart = undefined;
        quoteOpenedEscaped = false;
        segment.structuredClosures.length = 0;
        resetCommandSegmentContext(segment);
        index++;
        continue;
      }
    }
    if (startsSensitiveAttachedValue) sensitiveAttachedSeen = true;
    if (isOptionSeparator) optionSeparatorSeen = true;
    decoded += char;
    observeCommandSegmentChar(
      segment,
      char,
      value[index + 1],
      value[index + 2],
    );
    if (optionStartsAfterBoundary) {
      optionDecodedStart = decoded.length;
      optionSeparatorSeen = false;
    }
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
    openQuoteStart: quoteStart,
    openQuoteEscaped: quoteOpenedEscaped,
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

interface CommandValueContinuation {
  quote?: "'" | '"';
  escaped: boolean;
  crossedLine: boolean;
}

interface PositionalCredentialField {
  prefix: string;
  value: string;
  suffix: string;
  authorization: boolean;
}

function isDriveLikeCommandValue(value: string): boolean {
  return /(?:^|[=:([{<])[A-Za-z]:[\\/]/.test(value);
}

function positionalCredentialField(
  value: string,
  rawValue = value,
): PositionalCredentialField | undefined {
  if (isDriveLikeCommandValue(rawValue)) return undefined;

  const embeddedOption = commandOptionView(value);
  if (embeddedOption?.option?.kind === "attached") {
    const marker = embeddedOption.option.redactedToken.indexOf("[REDACTED]");
    const optionToken = value.slice(
      embeddedOption.prefix.length,
      value.length - embeddedOption.suffix.length,
    );
    const separator = optionToken.search(/[=:]/);
    if (marker >= 0 && separator > 0) {
      return {
        prefix:
          embeddedOption.prefix +
          embeddedOption.option.redactedToken.slice(0, marker),
        value: optionToken.slice(separator + 1),
        suffix: embeddedOption.suffix,
        authorization: false,
      };
    }
  }
  if (
    embeddedOption?.option?.kind === "separate" &&
    embeddedOption.prefix
  ) {
    return {
      prefix:
        embeddedOption.prefix +
        embeddedOption.option.redactedToken,
      value: "",
      suffix: embeddedOption.suffix,
      authorization: false,
    };
  }

  let keyStart = 0;
  const structuredContext = commandSegmentContext();
  for (let index = 0; index < value.length; index++) {
    const char = value[index]!;
    if (char === "=" || char === ":") {
      const key = value.slice(keyStart, index);
      const keyTokens = semanticKeyTokens(key);
      const authorization = keyTokens.at(-1) === "authorization";
      if (
        !isStructuredCommandSegment(structuredContext) &&
        (authorization || isSensitiveCredentialKey(key))
      ) {
        let valueStart = index + 1;
        while (value[valueStart] === " " || value[valueStart] === "\t") {
          valueStart++;
        }
        return {
          prefix: value.slice(0, valueStart),
          value: value.slice(valueStart),
          suffix: "",
          authorization,
        };
      }
      keyStart = index + 1;
    }
    observeCommandSegmentChar(
      structuredContext,
      char,
      value[index + 1],
      value[index + 2],
    );
  }
  return undefined;
}

/**
 * Continue one already-bound sensitive logical value. Once continuation state
 * exists, every character through the next unquoted whitespace belongs to that
 * value: punctuation, option-shaped fragments, and exact `--` text are data,
 * not fresh option syntax. Quote and trailing-escape state are carried across
 * physical lines, while the caller retains authority over explicit record
 * boundaries.
 */
function scanCommandValueContinuation(
  value: string,
  start: number,
  lineEnd: number,
  continuation: CommandValueContinuation,
): {
  end: number;
  quote?: "'" | '"';
  trailingEscape: boolean;
} {
  let quote = continuation.quote;
  let index = start;

  while (index < lineEnd) {
    const char = value[index]!;
    if (!quote && (char === " " || char === "\t")) break;

    if (char === "\\") {
      if (index + 1 < lineEnd) {
        index += 2;
        continue;
      }
      index++;
      continue;
    }

    if (char === "'" || char === '"') {
      if (!quote) quote = char;
      else if (quote === char) quote = undefined;
    }
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
    end: index,
    quote,
    trailingEscape: trailingBackslashes % 2 === 1,
  };
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
function redactCommandTokens(
  value: string,
  allowEndOfOptions = true,
  remainingQuoteRecoveries = MAX_UNTERMINATED_COMMAND_QUOTE_RECOVERIES,
  literalOptionSyntax = false,
): string {
  const parts: string[] = [];
  let outputCursor = 0;
  let lineStart = 0;
  let redactNext = false;
  let pendingCrossedLine = false;
  let endOfOptions = false;
  let positionalCredentialPending = false;
  let redactAuthorizationTail = false;
  let valueContinuation: CommandValueContinuation | undefined;

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
      if (tokenCursor < lineEnd) {
        const fragment = scanCommandValueContinuation(
          value,
          tokenCursor,
          lineEnd,
          valueContinuation,
        );
        parts.push(
          value.slice(outputCursor, tokenCursor),
          "[REDACTED]",
        );
        outputCursor = fragment.end;
        valueContinuation = fragment.quote || fragment.trailingEscape
          ? {
              quote: fragment.quote,
              escaped: fragment.trailingEscape,
              crossedLine: false,
            }
          : undefined;
        tokenCursor = fragment.end;
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
        !redactNext,
        redactNext && !literalOptionSyntax,
      );
      const raw = value.slice(item.start, item.end);
      const exactEndOfOptions =
        allowEndOfOptions && isExactCommandEndOfOptions(item, raw);
      const optionView = !endOfOptions
        ? commandOptionView(literalOptionSyntax ? raw : item.decoded)
        : undefined;
      const nextOptionView =
        redactNext && !exactEndOfOptions
          ? completeCommandOptionView(item)
          : undefined;

      if (redactNext) {
        if (exactEndOfOptions) {
          redactNext = false;
        } else {
          const bareLineContinuation =
            !item.quoted &&
            item.trailingEscape &&
            item.decoded === "\\";
          if (bareLineContinuation) {
            pendingCrossedLine = false;
            tokenCursor = item.end;
            continue;
          }
          if (nextOptionView) {
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
      }

      pendingCrossedLine = false;
      if (endOfOptions) {
        if (redactAuthorizationTail) {
          if (item.decoded.length > 0) {
            parts.push(
              value.slice(outputCursor, item.start),
              replaceCommandValue(raw, item.quoted || item.escaped),
            );
            outputCursor = item.end;
          }
          tokenCursor = item.end;
          continue;
        }
        if (positionalCredentialPending) {
          if (item.decoded.length === 0) {
            tokenCursor = item.end;
            continue;
          }
          parts.push(
            value.slice(outputCursor, item.start),
            replaceCommandValue(raw, item.quoted || item.escaped),
          );
          outputCursor = item.end;
          positionalCredentialPending = false;
          tokenCursor = item.end;
          continue;
        }

        const field = positionalCredentialField(item.decoded, raw);
        if (field) {
          if (field.value.trim()) {
            parts.push(
              value.slice(outputCursor, item.start),
              replaceCommandToken(
                raw,
                `${field.prefix}[REDACTED]${field.suffix}`,
              ),
            );
            outputCursor = item.end;
          } else if (field.authorization) {
            redactAuthorizationTail = true;
          } else {
            positionalCredentialPending = true;
          }
          if (field.authorization) redactAuthorizationTail = true;
          tokenCursor = item.end;
          continue;
        }
      } else if (exactEndOfOptions) {
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
      } else if (
        !endOfOptions &&
        item.openQuote &&
        item.openQuoteStart !== undefined &&
        !item.openQuoteEscaped
      ) {
        const recoveryStart = item.openQuoteStart + 1;
        const suffix = value.slice(recoveryStart, item.end);
        const recovered =
          remainingQuoteRecoveries > 0
            ? redactCommandTokens(
                suffix,
                allowEndOfOptions,
                remainingQuoteRecoveries - 1,
                true,
              )
            : "[REDACTED]";
        if (recovered !== suffix) {
          parts.push(
            value.slice(outputCursor, recoveryStart),
            recovered,
          );
          outputCursor = item.end;
        }
      }
      tokenCursor = item.end;
    }

    if (lineEnd >= value.length) break;
    endOfOptions = false;
    positionalCredentialPending = false;
    redactAuthorizationTail = false;
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
      const redacted = redactCommandTokens(inner, false);
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

function redactDiagnosticQuotedCommands(value: string): string {
  const parts: string[] = [];
  let outputCursor = 0;
  let found = false;
  let lineStart = 0;

  while (lineStart < value.length) {
    const lineEnd = physicalLineEnd(value, lineStart);
    const line = value.slice(lineStart, lineEnd);
    const opener = /(?:^|[:=])[ \t]*(["'])/g;
    for (
      let match = opener.exec(line);
      match;
      match = opener.exec(line)
    ) {
      const quote = match[1]!;
      const open = lineStart + match.index + match[0].lastIndexOf(quote);
      let close = -1;
      for (let index = open + 1; index < lineEnd; index++) {
        if (value[index] === "\\") {
          index++;
          continue;
        }
        if (value[index] === quote) close = index;
      }
      if (close < 0) continue;

      const inner = value.slice(open + 1, close);
      const redacted = redactCommandTokens(inner);
      if (redacted !== inner) {
        parts.push(
          redactOrdinaryCommandText(value.slice(outputCursor, open)),
          quote,
          redacted,
          quote,
        );
        outputCursor = close + 1;
        found = true;
      }
      break;
    }
    lineStart = lineEnd < value.length
      ? lineBreakEnd(value, lineEnd)
      : value.length;
  }

  if (!found) return redactOrdinaryCommandText(value);
  parts.push(redactOrdinaryCommandText(value.slice(outputCursor)));
  return parts.join("");
}

function redactOrdinaryCommandText(value: string): string {
  return redactQuotedCommandSegments(
    redactCommandTokens(value),
  );
}

function redactCommandText(value: string): string {
  return redactDiagnosticQuotedCommands(value);
}

/** Redact values that follow credential-bearing command-line flags. */
export function redactArgv(argv: string[]): string[] {
  const redacted: string[] = [];
  let redactNext = false;
  let endOfOptions = false;
  let positionalCredentialPending = false;
  let redactAuthorizationTail = false;
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    if (endOfOptions) {
      if (redactAuthorizationTail) {
        redacted.push(arg ? "[REDACTED]" : arg);
        continue;
      }
      if (positionalCredentialPending) {
        if (!arg) {
          redacted.push(arg);
          continue;
        }
        redacted.push("[REDACTED]");
        positionalCredentialPending = false;
        continue;
      }

      const field = positionalCredentialField(arg);
      if (field) {
        if (field.authorization) {
          redacted.push(
            field.value.trim()
              ? `${field.prefix}[REDACTED]${field.suffix}`
              : field.prefix,
          );
          redactAuthorizationTail = true;
          continue;
        }
        if (!field.value.trim()) {
          redacted.push(`${field.prefix}${field.suffix}`);
          positionalCredentialPending = true;
          continue;
        }
        redacted.push(`${field.prefix}[REDACTED]${field.suffix}`);
        continue;
      }
      redacted.push(redactText(arg));
      continue;
    }
    if (arg === "--") {
      redacted.push(arg);
      redactNext = false;
      endOfOptions = true;
      continue;
    }
    if (redactNext) {
      const chainedOption = credentialOption(arg, true);
      if (chainedOption?.kind === "attached") {
        redacted.push(chainedOption.redactedToken);
        redactNext = false;
        continue;
      }
      if (chainedOption?.kind === "separate") {
        redacted.push(chainedOption.redactedToken);
        continue;
      }
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
const PUBLIC_VALUE_TRUNCATED = "[TRUNCATED]";
const PUBLIC_VALUE_TRUNCATED_KEY = "[TRUNCATED]";
const MAX_PUBLIC_VALUE_DEPTH = 64;
const MAX_PUBLIC_VALUE_OBJECTS = 10_000;
const MAX_PUBLIC_VALUE_ENTRIES = 10_000;
const COMMAND_ARGUMENT_ARRAY_KEYS = new Set([
  "args",
  "arguments",
  "argv",
  "command",
]);

interface PublicValueFrame {
  value: unknown;
  depth: number;
  key?: string;
  assign: (projected: unknown) => void;
}

function publicValue(value: unknown): unknown {
  const root: { value: unknown } = { value: null };
  const seen = new WeakSet<object>();
  const stack: PublicValueFrame[] = [{
    value,
    depth: 0,
    assign: (projected) => {
      root.value = projected;
    },
  }];
  let objectCount = 0;

  while (stack.length > 0) {
    const frame = stack.pop()!;
    const current = frame.value;
    if (typeof current === "string") {
      frame.assign(redactText(current));
      continue;
    }
    if (
      current === null ||
      typeof current === "boolean" ||
      (typeof current === "number" && Number.isFinite(current))
    ) {
      frame.assign(current);
      continue;
    }
    if (typeof current !== "object") {
      frame.assign(null);
      continue;
    }
    if (
      frame.depth >= MAX_PUBLIC_VALUE_DEPTH ||
      objectCount >= MAX_PUBLIC_VALUE_OBJECTS
    ) {
      frame.assign(PUBLIC_VALUE_TRUNCATED);
      continue;
    }
    if (utilTypes.isProxy(current) || seen.has(current)) {
      frame.assign(null);
      continue;
    }

    const isArray = Array.isArray(current);
    let prototype: object | null;
    let descriptors: PropertyDescriptorMap;
    try {
      prototype = Object.getPrototypeOf(current);
      if (
        (!isArray && prototype !== Object.prototype && prototype !== null) ||
        (isArray && prototype !== Array.prototype)
      ) {
        frame.assign(null);
        continue;
      }
      descriptors = Object.getOwnPropertyDescriptors(current);
    } catch {
      frame.assign(null);
      continue;
    }

    seen.add(current);
    objectCount++;
    if (isArray) {
      const length = descriptors["length"]?.value;
      if (
        typeof length !== "number" ||
        !Number.isSafeInteger(length) ||
        length < 0
      ) {
        frame.assign(null);
        continue;
      }
      const boundedLength = Math.min(length, MAX_PUBLIC_VALUE_ENTRIES);
      if (
        frame.key &&
        COMMAND_ARGUMENT_ARRAY_KEYS.has(frame.key.toLowerCase())
      ) {
        const argv: string[] = [];
        let completeArgv = true;
        for (let index = 0; index < boundedLength; index++) {
          const descriptor = descriptors[String(index)];
          if (
            !descriptor?.enumerable ||
            !("value" in descriptor) ||
            typeof descriptor.value !== "string"
          ) {
            completeArgv = false;
            break;
          }
          argv.push(descriptor.value);
        }
        if (completeArgv) {
          const result: unknown[] = redactArgv(argv);
          if (length > boundedLength) result.push(PUBLIC_VALUE_TRUNCATED);
          frame.assign(result);
          continue;
        }
        frame.assign([PUBLIC_VALUE_TRUNCATED]);
        continue;
      }

      const result: unknown[] = [];
      result.length = boundedLength + (length > boundedLength ? 1 : 0);
      if (length > boundedLength) {
        result[boundedLength] = PUBLIC_VALUE_TRUNCATED;
      }
      frame.assign(result);

      const children: Array<[number, unknown]> = [];
      for (const key of Object.keys(descriptors)) {
        const descriptor = descriptors[key]!;
        const numeric = Number(key);
        if (
          !descriptor.enumerable ||
          !("value" in descriptor) ||
          !Number.isSafeInteger(numeric) ||
          numeric < 0 ||
          String(numeric) !== key ||
          numeric >= boundedLength
        ) {
          continue;
        }
        children.push([numeric, descriptor.value]);
      }
      for (let index = children.length - 1; index >= 0; index--) {
        const [numeric, nested] = children[index]!;
        stack.push({
          value: nested,
          depth: frame.depth + 1,
          assign: (projected) => {
            result[numeric] = projected;
          },
        });
      }
      continue;
    }

    const result: Record<string, unknown> = Object.create(null);
    frame.assign(result);
    const children: Array<[string, unknown]> = [];
    let entryCount = 0;
    let entriesTruncated = false;
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]!;
      if (
        POLLUTION_KEYS.has(key) ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        continue;
      }
      if (entryCount >= MAX_PUBLIC_VALUE_ENTRIES) {
        entriesTruncated = true;
        break;
      }
      entryCount++;
      if (isSensitiveCredentialKey(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = null;
        children.push([key, descriptor.value]);
      }
    }
    if (entriesTruncated) {
      result[PUBLIC_VALUE_TRUNCATED_KEY] = true;
    }
    for (let index = children.length - 1; index >= 0; index--) {
      const [key, nested] = children[index]!;
      stack.push({
        value: nested,
        depth: frame.depth + 1,
        key,
        assign: (projected) => {
          result[key] = projected;
        },
      });
    }
  }

  return root.value;
}

/** Redact credential-bearing keys and nested string diagnostics in public data. */
export function redactPublicValue(value: unknown): unknown {
  return publicValue(value);
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
