import { expect, test } from "bun:test";
import { redactText } from "./lib/redaction.js";

test("sensitive request headers redact their complete values", () => {
  const samples = [
    {
      input:
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE12345678/20260727/us-east-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=deadbeefcafebabe",
      secrets: [
        "AWS4-HMAC-SHA256",
        "AKIAEXAMPLE12345678",
        "SignedHeaders",
        "deadbeefcafebabe",
      ],
    },
    {
      input:
        'pRoXy-AuThOrIzAtIoN \t:   Digest username="operator", realm="proxy", nonce="nonce-value", response="response-value"',
      secrets: ["Digest", "operator", "proxy", "nonce-value", "response-value"],
    },
    {
      input: 'Cookie: session=session-secret; theme="night,blue"; csrf=csrf-secret',
      secrets: ["session-secret", "night,blue", "csrf-secret"],
    },
    {
      input:
        'SET-COOKIE = session=session-secret; Path=/; HttpOnly, preference="dark,blue"; SameSite=Lax',
      secrets: ["session-secret", "Path=/", "dark,blue", "SameSite=Lax"],
    },
    {
      input:
        '{"Authorization":"AWS4-HMAC-SHA256 Credential=quoted-secret, SignedHeaders=host, Signature=quoted-signature","status":403,"message":"denied"}',
      secrets: ["AWS4-HMAC-SHA256", "quoted-secret", "SignedHeaders", "quoted-signature"],
      retained: ['"status":403', '"message":"denied"'],
    },
  ];

  for (const sample of samples) {
    const redacted = redactText(sample.input);
    expect(redacted).toContain("[REDACTED]");
    for (const secret of sample.secrets) expect(redacted).not.toContain(secret);
    for (const retained of sample.retained ?? []) expect(redacted).toContain(retained);
  }
});

test("request-header redaction leaves unrelated prose and fields unchanged", () => {
  const unrelated = [
    "status=401 message=authorization failed",
    "cookie policy allows SameSite=Lax",
    "Set-Cookie documentation is available",
    "Use Bearer authentication for this endpoint",
    "Basic authentication is disabled",
    "authorization-mode: public-capability-name",
  ].join("\n");

  expect(redactText(unrelated)).toBe(unrelated);
});

test("an unterminated quoted header value does not consume later diagnostic lines", () => {
  const input = 'Cookie: "unterminated-secret\nstatus=502 message=upstream failed';
  const redacted = redactText(input);

  expect(redacted).not.toContain("unterminated-secret");
  expect(redacted).toContain("status=502 message=upstream failed");
});

test("folded sensitive request headers redact every syntactic continuation", () => {
  const input = [
    "request attempt=1",
    "Authorization: AWS4-HMAC-SHA256 Credential=folded-access/20260727/us-east-1/bedrock/aws4_request,\r",
    "\tSignedHeaders=content-type;host;x-amz-date,\r",
    " Signature=folded-signature\r",
    "status=403 request-id=independent-diagnostic",
    "pRoXy-AuThOrIzAtIoN: Digest username=\"folded-proxy-user\",\r",
    "\tnonce=\"folded-proxy-nonce\", response=\"folded-proxy-response\"\r",
    "proxy-status=407 proxy-request-id=independent-proxy-diagnostic",
    "Cookie: session=folded-session;",
    ' theme="night,blue";',
    "\tcsrf=folded-csrf",
    "retryable=false",
    "Set-Cookie: first=folded-first;",
    "\tPath=/; HttpOnly,",
    " second=folded-second; SameSite=Lax",
    "completed=false",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "folded-access",
    "SignedHeaders",
    "folded-signature",
    "folded-proxy-user",
    "folded-proxy-nonce",
    "folded-proxy-response",
    "folded-session",
    "night,blue",
    "folded-csrf",
    "folded-first",
    "Path=/",
    "folded-second",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "request attempt=1",
    "status=403 request-id=independent-diagnostic",
    "proxy-status=407 proxy-request-id=independent-proxy-diagnostic",
    "retryable=false",
    "completed=false",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("an empty sensitive header never consumes the next diagnostic line", () => {
  const input = [
    "Authorization:   ",
    "status=401 message=empty authorization header",
    "Proxy-Authorization=\t",
    "proxy-status=407 message=empty proxy authorization header",
  ].join("\n");

  expect(redactText(input)).toBe(input);
});

test("sensitive header matching handles safe delimiters without broad prose redaction", () => {
  const input = [
    "pRoXy-AuThOrIzAtIoN='Digest username=\"quoted-user\", nonce=\"quoted-nonce\"'",
    'COOKIE = "session=quoted-session; theme=blue"',
    "authorization-mode = public-capability-name",
    "Set-Cookie documentation: independent prose",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of ["quoted-user", "quoted-nonce", "quoted-session"]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("authorization-mode = public-capability-name");
  expect(redacted).toContain("Set-Cookie documentation: independent prose");
});

test("closing brackets and braces inside sensitive values are fully redacted", () => {
  const input = [
    "Cookie: session=cookie-secret]cookie-suffix}; theme=night",
    "Authorization: Custom auth-secret]auth-suffix}",
    "Set-Cookie: session=set-cookie-secret]set-cookie-suffix}; Path=/",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "cookie-secret",
    "cookie-suffix",
    "auth-secret",
    "auth-suffix",
    "set-cookie-secret",
    "set-cookie-suffix",
    "Path=/",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(3);
});

test("indented diagnostics and adjacent headers are not mistaken for folded secrets", () => {
  const input = [
    "Authorization: AWS4-HMAC-SHA256 Credential=folded-access/20260727/us-east-1/bedrock/aws4_request,",
    "  SignedHeaders=content-type;host;x-amz-date,",
    "  Signature=folded-signature",
    "  status=403 request-id=keep-indented-diagnostic",
    "  X-Request-ID: keep-adjacent-header",
    "",
    "Cookie: session=folded-cookie;",
    "  theme=night;",
    "  csrf=folded-csrf",
    "  status=429 retry-after=keep-cookie-diagnostic",
    "message=keep-unindented-diagnostic",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "folded-access",
    "SignedHeaders",
    "folded-signature",
    "folded-cookie",
    "folded-csrf",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const retained of [
    "status=403 request-id=keep-indented-diagnostic",
    "X-Request-ID: keep-adjacent-header",
    "status=429 retry-after=keep-cookie-diagnostic",
    "message=keep-unindented-diagnostic",
  ]) {
    expect(redacted).toContain(retained);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(2);
});

test("blank, quoted, and adjacent serialized boundaries retain non-sensitive data", () => {
  const input = [
    'Cookie: "quoted-secret]with-brace}"',
    "  status=200 keep-after-quoted",
    "",
    '{"Authorization":"serialized-secret]with-brace}","status":401,"message":"keep-serialized"}',
    "X-Diagnostic: keep-final-header",
  ].join("\n");

  const redacted = redactText(input);

  expect(redacted).not.toContain("quoted-secret");
  expect(redacted).not.toContain("serialized-secret");
  expect(redacted).toContain("status=200 keep-after-quoted");
  expect(redacted).toContain('"status":401');
  expect(redacted).toContain('"message":"keep-serialized"');
  expect(redacted).toContain("X-Diagnostic: keep-final-header");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(2);
});
