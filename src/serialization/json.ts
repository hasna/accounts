import { createHash } from "node:crypto";

import { AccountsError } from "../errors";

const MAX_JSON_BYTES = 1_048_576;
const MAX_JSON_DEPTH = 32;
const MAX_CONTAINER_ITEMS = 10_000;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SENSITIVE_KEYS = /^(?:access[_-]?token|api[_-]?key|auth(?:entication|orization)?|authorization|bearer|client[_-]?secret|cookie|credentials?|credential[_-]?handle|credential[_-]?value|id[_-]?token|password|private[_-]?key|refresh[_-]?token|secret(?:[_-]?key|[_-]?ref)?|session[_-]?token|setup[_-]?token|token|vault[_-]?path|role[_-]?arn|local[_-]?path)$/i;

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

function assertJsonValue(value: unknown, depth: number, seen: Set<object>): void {
  if (depth > MAX_JSON_DEPTH) {
    throw new AccountsError("VALIDATION_FAILED", "JSON nesting is too deep");
  }
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (hasInvalidUnicode(value)) {
      throw new AccountsError("VALIDATION_FAILED", "Invalid Unicode in JSON string");
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new AccountsError("VALIDATION_FAILED", "JSON number must be finite");
    }
    return;
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
    for (const item of value) assertJsonValue(item, depth + 1, seen);
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new AccountsError("VALIDATION_FAILED", "Only plain JSON objects are accepted");
    }
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_CONTAINER_ITEMS) {
      throw new AccountsError("VALIDATION_FAILED", "JSON object is too large");
    }
    for (const [key, item] of entries) {
      if (FORBIDDEN_KEYS.has(key)) {
        throw new AccountsError("VALIDATION_FAILED", "Reserved object key is forbidden");
      }
      assertJsonValue(item, depth + 1, seen);
    }
  }
  seen.delete(value);
}

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value).sort()) {
      result[key] = sorted((value as Record<string, unknown>)[key]);
    }
    return result;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  assertJsonValue(value, 0, new Set());
  return JSON.stringify(sorted(value));
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
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) throw new AccountsError("VALIDATION_FAILED", "Cyclic JSON is forbidden");
  seen.add(value);
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEYS.test(key)) {
      throw new AccountsError("VALIDATION_FAILED", "Credential material or locator fields are forbidden", {
        details: { field: key },
      });
    }
    assertNoSensitiveFields(item, `${path}.${key}`, seen);
  }
  seen.delete(value);
}

export function isSensitiveFieldName(key: string): boolean {
  return SENSITIVE_KEYS.test(key);
}
