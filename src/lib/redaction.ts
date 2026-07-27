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
const SENSITIVE_KEY_QUALIFIERS = new Set([
  "api",
  "private",
  "signing",
  "webhook",
  "auth",
  "authorization",
  "access",
  "consumer",
  "bearer",
  "oauth",
  "session",
  "secret",
  "service",
  "account",
  "x",
  "goog",
  "amz",
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
 * normalization. The terminal-token rule intentionally avoids substring
 * matches such as `tokenBucket`, `passwordless`, `secretariat`, and `monkey`.
 */
export function isSensitiveCredentialKey(value: string): boolean {
  const tokens = semanticKeyTokens(value);
  if (tokens.length === 0) return false;

  const compact = tokens.join("");
  if (SENSITIVE_EXACT_KEYS.has(compact)) return true;

  const terminal = tokens[tokens.length - 1]!;
  if (SENSITIVE_TERMINAL_TOKENS.has(terminal)) return true;
  if (terminal !== "key") return false;
  return tokens.slice(0, -1).some((token) => SENSITIVE_KEY_QUALIFIERS.has(token));
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
    redactEscapedSerializedFields(value),
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

    const normalizedArg = arg
      .normalize("NFKC")
      .replace(/^[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]+/, (dashes) =>
        "-".repeat(dashes.length),
      );

    const separator = normalizedArg.search(/[=:]/);
    if (
      separator > 0 &&
      isSensitiveCredentialKey(normalizedArg.slice(0, separator))
    ) {
      redacted.push(`${normalizedArg.slice(0, separator + 1)}[REDACTED]`);
      continue;
    }

    const shortOption = /^-(?!-)(.*)$/.exec(normalizedArg)?.[1];
    const shortCredentialIndex = shortOption?.toLowerCase().indexOf("k") ?? -1;
    if (
      shortOption &&
      shortCredentialIndex >= 0 &&
      /^[A-Za-z]+$/.test(shortOption.slice(0, shortCredentialIndex + 1))
    ) {
      if (shortCredentialIndex === shortOption.length - 1) {
        redacted.push(normalizedArg);
        redactNext = true;
      } else {
        redacted.push(
          `-${shortOption.slice(0, shortCredentialIndex + 1)}[REDACTED]`,
        );
      }
      continue;
    }

    redacted.push(redactText(arg));
    if (isSensitiveCredentialKey(normalizedArg)) redactNext = true;
  }
  return redacted;
}

/** Redact credential-bearing keys and nested string diagnostics in public data. */
export function redactPublicValue(value: unknown): unknown {
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map((entry) => redactPublicValue(entry));
  if (!value || typeof value !== "object") return value;

  const result: Record<string, unknown> = Object.create(null);
  for (const [key, nested] of Object.entries(value)) {
    result[key] = isSensitiveCredentialKey(key)
      ? "[REDACTED]"
      : redactPublicValue(nested);
  }
  return result;
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
