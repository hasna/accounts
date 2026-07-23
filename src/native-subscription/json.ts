import { createHash } from "node:crypto";

import { AccountsError } from "./errors.js";

const MAX_JSON_BYTES = 1_048_576;
const MAX_JSON_DEPTH = 32;
const MAX_CONTAINER_ITEMS = 10_000;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SENSITIVE_KEYS = /^(?:access[_-]?token|api[_-]?key|auth(?:entication|orization)?|authorization|bearer|client[_-]?secret|cookie|credentials?|credential[_-]?handle|credential[_-]?value|id[_-]?token|password|private[_-]?key|refresh[_-]?token|secret(?:[_-]?key|[_-]?ref)?|session[_-]?token|setup[_-]?token|token|vault[_-]?path|role[_-]?arn|local[_-]?path)$/i;
const SUSPECT_VALUE_PATTERNS = [
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[oprsu]_[A-Za-z0-9]{20,}\b/,
  /\b(?:sk|rk|pk|token|secret)[-_][A-Za-z0-9_-]{16,}\b/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
] as const;

function hasInvalidUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class ClosedJsonParser {
  private offset = 0;

  constructor(private readonly source: string) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.offset !== this.source.length) this.fail("Unexpected trailing JSON data");
    return value;
  }

  private parseValue(depth: number): unknown {
    if (depth > MAX_JSON_DEPTH) this.fail("JSON nesting is too deep");
    const character = this.source[this.offset];
    switch (character) {
      case "{":
        return this.parseObject(depth + 1);
      case "[":
        return this.parseArray(depth + 1);
      case '"':
        return this.parseString();
      case "t":
        return this.parseLiteral("true", true);
      case "f":
        return this.parseLiteral("false", false);
      case "n":
        return this.parseLiteral("null", null);
      default:
        if (character === "-" || (character !== undefined && /[0-9]/.test(character))) {
          return this.parseNumber();
        }
        return this.fail("Invalid JSON value");
    }
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.offset += 1;
    this.skipWhitespace();
    const result = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    if (this.source[this.offset] === "}") {
      this.offset += 1;
      return result;
    }
    while (true) {
      if (this.source[this.offset] !== '"') this.fail("Object key must be a string");
      const key = this.parseString();
      if (FORBIDDEN_KEYS.has(key)) this.fail("Reserved object key is forbidden");
      if (keys.has(key)) this.fail("Duplicate object key is forbidden");
      keys.add(key);
      if (keys.size > MAX_CONTAINER_ITEMS) this.fail("JSON object is too large");
      this.skipWhitespace();
      if (this.source[this.offset] !== ":") this.fail("Missing object separator");
      this.offset += 1;
      this.skipWhitespace();
      result[key] = this.parseValue(depth);
      this.skipWhitespace();
      const separator = this.source[this.offset];
      if (separator === "}") {
        this.offset += 1;
        return result;
      }
      if (separator !== ",") this.fail("Missing object item separator");
      this.offset += 1;
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): unknown[] {
    this.offset += 1;
    this.skipWhitespace();
    const result: unknown[] = [];
    if (this.source[this.offset] === "]") {
      this.offset += 1;
      return result;
    }
    while (true) {
      result.push(this.parseValue(depth));
      if (result.length > MAX_CONTAINER_ITEMS) this.fail("JSON array is too large");
      this.skipWhitespace();
      const separator = this.source[this.offset];
      if (separator === "]") {
        this.offset += 1;
        return result;
      }
      if (separator !== ",") this.fail("Missing array item separator");
      this.offset += 1;
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.offset;
    this.offset += 1;
    let escaped = false;
    while (this.offset < this.source.length) {
      const character = this.source[this.offset]!;
      if (!escaped && character === '"') {
        this.offset += 1;
        const token = this.source.slice(start, this.offset);
        try {
          const parsed = JSON.parse(token) as string;
          if (hasInvalidUnicode(parsed)) this.fail("Invalid Unicode in JSON string");
          return parsed;
        } catch {
          return this.fail("Invalid JSON string");
        }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) this.fail("Control character in JSON string");
      if (!escaped && character === "\\") {
        escaped = true;
      } else {
        escaped = false;
      }
      this.offset += 1;
    }
    return this.fail("Unterminated JSON string");
  }

  private parseNumber(): number {
    const remaining = this.source.slice(this.offset);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remaining);
    if (match === null) return this.fail("Invalid JSON number");
    this.offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      return this.fail("Unsafe JSON number; counters must use decimal strings");
    }
    if (Object.is(value, -0) || JSON.stringify(value) !== match[0]) {
      return this.fail("JSON number is not in canonical form");
    }
    return value;
  }

  private parseLiteral<T>(token: string, value: T): T {
    if (!this.source.startsWith(token, this.offset)) return this.fail("Invalid JSON literal");
    this.offset += token.length;
    return value;
  }

  private skipWhitespace(): void {
    while (/[ \t\r\n]/.test(this.source[this.offset] ?? "")) this.offset += 1;
  }

  private fail(message: string): never {
    throw new AccountsError("VALIDATION_FAILED", message);
  }
}

export function parseClosedJson(source: string): unknown {
  if (Buffer.byteLength(source, "utf8") > MAX_JSON_BYTES) {
    throw new AccountsError("VALIDATION_FAILED", "JSON document is too large");
  }
  return new ClosedJsonParser(source).parse();
}

export function parseClosedJsonBytes(source: Uint8Array): unknown {
  if (source.byteLength > MAX_JSON_BYTES) {
    throw new AccountsError("VALIDATION_FAILED", "JSON document is too large");
  }
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    throw new AccountsError("VALIDATION_FAILED", "JSON must be valid UTF-8");
  }
  return parseClosedJson(decoded);
}

function snapshotJson(value: unknown, depth: number, seen: Set<object>): unknown {
  if (depth > MAX_JSON_DEPTH) {
    throw new AccountsError("VALIDATION_FAILED", "JSON nesting is too deep");
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (hasInvalidUnicode(value)) {
      throw new AccountsError("VALIDATION_FAILED", "Invalid Unicode in JSON string");
    }
    return value;
  }
  if (typeof value === "number") {
    if (
      !Number.isFinite(value) ||
      Object.is(value, -0) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value))
    ) {
      throw new AccountsError("VALIDATION_FAILED", "JSON number is not safely canonicalizable");
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new AccountsError("VALIDATION_FAILED", "Value is not JSON serializable");
  }
  if (seen.has(value)) throw new AccountsError("VALIDATION_FAILED", "Cyclic JSON is forbidden");
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_CONTAINER_ITEMS) {
      throw new AccountsError("VALIDATION_FAILED", "JSON array is too large");
    }
    const result = value.map((item) => snapshotJson(item, depth + 1, seen));
    seen.delete(value);
    return result;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new AccountsError("VALIDATION_FAILED", "Only plain JSON objects are accepted");
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new AccountsError("VALIDATION_FAILED", "Symbol properties are forbidden in JSON");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors);
    if (keys.length > MAX_CONTAINER_ITEMS) {
      throw new AccountsError("VALIDATION_FAILED", "JSON object is too large");
    }
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of keys.sort()) {
      const descriptor = descriptors[key]!;
      if (FORBIDDEN_KEYS.has(key)) {
        throw new AccountsError("VALIDATION_FAILED", "Reserved object key is forbidden");
      }
      if (!descriptor.enumerable) continue;
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) {
        throw new AccountsError("VALIDATION_FAILED", "Accessor properties are forbidden in JSON");
      }
      if (hasInvalidUnicode(key)) {
        throw new AccountsError("VALIDATION_FAILED", "Invalid Unicode in JSON object key");
      }
      result[key] = snapshotJson(descriptor.value, depth + 1, seen);
    }
    seen.delete(value);
    return result;
  }
}

function serializeCanonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(serializeCanonical).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${serializeCanonical(record[key])}`)
    .join(",")}}`;
}

export function canonicalJson(value: unknown): string {
  assertNoSensitiveFields(value);
  return serializeCanonical(snapshotJson(value, 0, new Set()));
}

export function canonicalSha256(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

export function assertNoSensitiveFields(value: unknown, path = "$", seen = new Set<object>()): void {
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new AccountsError("VALIDATION_FAILED", "Cyclic JSON is forbidden");
    seen.add(value);
    value.forEach((item, index) => assertNoSensitiveFields(item, `${path}[${index}]`, seen));
    seen.delete(value);
    return;
  }
  if (typeof value === "string") {
    assertNoSecretLikeString(value);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) throw new AccountsError("VALIDATION_FAILED", "Cyclic JSON is forbidden");
  seen.add(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new AccountsError("VALIDATION_FAILED", "Symbol properties are forbidden in DTOs");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new AccountsError("VALIDATION_FAILED", "Accessor properties are forbidden in DTOs");
    }
    if (SENSITIVE_KEYS.test(key)) {
      throw new AccountsError("VALIDATION_FAILED", "Credential material or locator fields are forbidden", {
        details: { field: key },
      });
    }
    assertNoSensitiveFields(descriptor.value, `${path}.${key}`, seen);
  }
  seen.delete(value);
}

export function isSensitiveFieldName(key: string): boolean {
  return SENSITIVE_KEYS.test(key);
}

export function assertNoSecretLikeString(value: string): void {
  if (SUSPECT_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
    throw new AccountsError("VALIDATION_FAILED", "A value resembles credential material");
  }
}
