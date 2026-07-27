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
