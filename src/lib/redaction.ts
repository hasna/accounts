import { types as utilTypes } from "node:util";

const SECRET_PATTERN =
  /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const CREDENTIAL_FIELD_PATTERN =
  /(^|[^A-Za-z0-9_. -])(["']?)([A-Za-z][A-Za-z0-9_. -]{0,63}?)\2[ \t]*[:=][ \t]*/gim;
const SERIALIZED_FIELD_PATTERN =
  /(^|[,{])([ \t]*)(("(?:\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4})|[^"\\\r\n])*")|('(?:\\(?:['"\\/bfnrt]|u[0-9A-Fa-f]{4})|[^'\\\r\n])*'))[ \t]*:[ \t]*/gm;
const HEADER_LINE_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:/;
const EXPLICIT_DIAGNOSTIC_RECORD_PATTERN =
  /^(?:status|message|stack|detail)[ \t]*=[ \t]*\S/i;
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
  return redactCommandText(
    redactSensitiveFields(
      redactEscapedSerializedFields(value),
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
  "(",
  "[",
  "{",
  ",",
  ";",
]);
const EMBEDDED_OPTION_TERMINATORS = new Set([
  ")",
  "]",
  "}",
  ",",
  ";",
]);

function commandOptionView(value: string): CommandOptionView | undefined {
  for (let start = 0; start < value.length; start++) {
    const previous = value[start - 1];
    if (
      (start !== 0 && !EMBEDDED_OPTION_BOUNDARIES.has(previous!)) ||
      !normalizeCommandToken(value[start]!).startsWith("-")
    ) {
      continue;
    }

    let end = start;
    while (
      end < value.length &&
      !EMBEDDED_OPTION_TERMINATORS.has(value[end]!)
    ) {
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
    start = Math.max(start, end - 1);
  }
  return undefined;
}

interface CommandToken {
  start: number;
  end: number;
  decoded: string;
}

function scanCommandToken(
  value: string,
  start: number,
  lineEnd: number,
): CommandToken {
  let decoded = "";
  let quote: "'" | '"' | undefined;
  let index = start;

  while (index < lineEnd) {
    const char = value[index]!;
    if (!quote && (char === " " || char === "\t")) break;
    if (char === "\\") {
      if (index + 1 < lineEnd) {
        const escaped = value[index + 1]!;
        if (escaped === "'" || escaped === '"') {
          if (!quote) {
            quote = escaped;
            index += 2;
            continue;
          }
          if (quote === escaped) {
            quote = undefined;
            index += 2;
            continue;
          }
        }
        decoded += escaped;
        index += 2;
        continue;
      }
      decoded += char;
      index++;
      continue;
    }
    if (char === "'" || char === '"') {
      if (!quote) {
        quote = char;
        index++;
        continue;
      }
      if (quote === char) {
        quote = undefined;
        index++;
        continue;
      }
    }
    decoded += char;
    index++;
  }

  return { start, end: index, decoded };
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

function replaceCommandValue(raw: string): string {
  const outer = outerQuotedParts(raw);
  return outer
    ? `${outer.quote}[REDACTED]${outer.quote}${outer.suffix}`
    : "[REDACTED]";
}

/**
 * Redact credential options embedded in captured command output. The scanner
 * is single-pass, quote-aware, line-bounded, and shares option classification
 * with `redactArgv`.
 */
function redactCommandTokens(value: string): string {
  const parts: string[] = [];
  let outputCursor = 0;
  let index = 0;

  while (index < value.length) {
    const lineEnd = physicalLineEnd(value, index);
    let tokenCursor = index;
    let redactNext = false;
    let endOfOptions = false;

    while (tokenCursor < lineEnd) {
      while (
        tokenCursor < lineEnd &&
        (value[tokenCursor] === " " || value[tokenCursor] === "\t")
      ) {
        tokenCursor++;
      }
      if (tokenCursor >= lineEnd) break;

      const token = scanCommandToken(value, tokenCursor, lineEnd);
      const raw = value.slice(token.start, token.end);
      const optionView = !endOfOptions
        ? commandOptionView(token.decoded)
        : undefined;

      if (redactNext) {
        if (
          optionView ||
          token.decoded.startsWith("-")
        ) {
          redactNext = false;
        } else {
          parts.push(
            value.slice(outputCursor, token.start),
            replaceCommandValue(raw),
          );
          outputCursor = token.end;
          redactNext = false;
          tokenCursor = token.end;
          continue;
        }
      }

      if (!endOfOptions && optionView?.endOfOptions) {
        endOfOptions = true;
      } else if (optionView?.option) {
        if (optionView.option.kind === "attached") {
          const retainedSuffix = /['"\\]/.test(raw)
            ? ""
            : optionView.suffix;
          parts.push(
            value.slice(outputCursor, token.start),
            replaceCommandToken(
              raw,
              `${optionView.prefix}${optionView.option.redactedToken}${retainedSuffix}`,
            ),
          );
          outputCursor = token.end;
        } else {
          redactNext = true;
        }
      }
      tokenCursor = token.end;
    }

    if (lineEnd >= value.length) break;
    index = lineBreakEnd(value, lineEnd);
  }

  if (outputCursor === 0) return value;
  parts.push(value.slice(outputCursor));
  return parts.join("");
}

function redactQuotedCommandSegments(value: string): string {
  const parts: string[] = [];
  let cursor = 0;
  let index = 0;

  while (index < value.length) {
    const quote = value[index];
    if (quote !== "'" && quote !== '"') {
      index++;
      continue;
    }

    const lineEnd = physicalLineEnd(value, index);
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
