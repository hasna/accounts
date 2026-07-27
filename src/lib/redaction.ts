const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;
const SECRET_FIELD_PATTERN =
  /(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-goog-api-key|x-amz-security-token|api[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|(?:access|refresh|id|session)[-_]?token|credential|password|secret|token)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer|Basic)\s+[^\s,;}\]]+|[^\s,;}\]]+)/gi;
const SECRET_AUTH_SCHEME_PATTERN = /\b(Bearer|Basic)\s+[A-Za-z0-9+/_=.-]+/gi;

/** Redact common credential values and credential-bearing request headers. */
export function redactText(value: string): string {
  return value
    .replace(SECRET_FIELD_PATTERN, "$1[REDACTED]")
    .replace(SECRET_AUTH_SCHEME_PATTERN, "$1 [REDACTED]")
    .replace(SECRET_PATTERN, "[REDACTED]");
}
