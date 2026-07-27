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

test("empty-first-line folded sensitive headers redact credential continuations", () => {
  const input = [
    "Authorization:\r",
    " Bearer empty-auth-secret\r",
    "X-Authorization-Diagnostic: keep-auth-adjacent\r",
    "Proxy-Authorization:",
    " Basic empty-proxy-secret",
    "Cookie:\r",
    " session=empty-cookie-secret; theme=night\r",
    "Set-Cookie:",
    " sid=empty-set-cookie-secret; Path=/",
    "status=401 keep-status",
    "message=keep-message",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "empty-auth-secret",
    "empty-proxy-secret",
    "empty-cookie-secret",
    "empty-set-cookie-secret",
    "theme=night",
    "Path=/",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "X-Authorization-Diagnostic: keep-auth-adjacent",
    "status=401 keep-status",
    "message=keep-message",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("delimiter-free folded credential tokens are fully redacted", () => {
  const input = [
    "Authorization: Bearer split-auth-",
    " token-middle-a-",
    " token-fragment-a",
    "Proxy-Authorization: Basic split-proxy-",
    "\ttoken-middle-b-",
    "\ttoken-fragment-b",
    "Cookie: session=split-cookie-",
    " token-middle-c-",
    " token-fragment-c",
    "Set-Cookie: sid=split-set-cookie-",
    "\ttoken-middle-d-",
    "\ttoken-fragment-d; Path=/",
    "status=429 keep-after-folded-tokens",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "split-auth-",
    "token-middle-a",
    "token-fragment-a",
    "split-proxy-",
    "token-middle-b",
    "token-fragment-b",
    "split-cookie-",
    "token-middle-c",
    "token-fragment-c",
    "split-set-cookie-",
    "token-middle-d",
    "token-fragment-d",
    "Path=/",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("status=429 keep-after-folded-tokens");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("authorization folding preserves arbitrary independent diagnostic assignments", () => {
  const input = [
    "Authorization: AWS4-HMAC-SHA256 Credential=diagnostic-access/20260727/us-east-1/bedrock/aws4_request,",
    " SignedHeaders=content-type;host;x-amz-date,",
    " Signature=diagnostic-signature,",
    " stack=Error: independent credential failure",
    " detail=Provider rejected request independently",
    " status=403 keep-status",
    " message=keep-message",
    " X-Request-ID: keep-adjacent-header",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of ["diagnostic-access", "SignedHeaders", "diagnostic-signature"]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "stack=Error: independent credential failure",
    "detail=Provider rejected request independently",
    "status=403 keep-status",
    "message=keep-message",
    "X-Request-ID: keep-adjacent-header",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(1);
});

test("empty sensitive headers preserve indented diagnostics instead of treating assignments as credentials", () => {
  const input = [
    "Authorization:",
    " stack=Error: authorization failed independently",
    "Proxy-Authorization:",
    " detail=Proxy rejected request independently",
    "Cookie:",
    " status=401 keep-cookie-status",
    "Set-Cookie:",
    " message=keep set-cookie message",
    "X-Request-ID: keep-adjacent-header",
  ].join("\n");

  expect(redactText(input)).toBe(input);
});

test("sensitive folds accept leading separators and padding-only credential tails", () => {
  const input = [
    "Authorization: AWS4-HMAC-SHA256 Credential=leading-auth/20260727/us-east-1/bedrock/aws4_request\r",
    " , SignedHeaders=content-type;host;x-amz-date\r",
    " , Signature=leading-auth-signature\r",
    "X-Auth-Diagnostic: keep-auth-boundary\r",
    "Proxy-Authorization: Digest username=\"leading-proxy-user\"",
    " , nonce=\"leading-proxy-nonce\"",
    " , response=\"leading-proxy-response\"",
    "X-Proxy-Diagnostic: keep-proxy-boundary",
    "Cookie: session=leading-cookie\r",
    " ; csrf=leading-csrf\r",
    "X-Cookie-Diagnostic: keep-cookie-boundary\r",
    "Set-Cookie: sid=leading-set-cookie",
    " ; Path=/",
    " ; HttpOnly",
    "X-Set-Cookie-Diagnostic: keep-set-cookie-boundary",
    "Authorization: Basic cGFkZGVkLWF1dGg",
    " ==",
    "Proxy-Authorization: Basic cGFkZGVkLXByb3h5",
    "\t==",
    "Cookie: padded=cGFkZGVkLWNvb2tpZQ",
    " ==",
    "Set-Cookie: padded=cGFkZGVkLXNldC1jb29raWU",
    "\t==; SameSite=Lax",
    "status=200 keep-final-boundary",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "leading-auth",
    "SignedHeaders",
    "leading-auth-signature",
    "leading-proxy-user",
    "leading-proxy-nonce",
    "leading-proxy-response",
    "leading-cookie",
    "leading-csrf",
    "leading-set-cookie",
    "Path=/",
    "cGFkZGVkLWF1dGg",
    "cGFkZGVkLXByb3h5",
    "cGFkZGVkLWNvb2tpZQ",
    "cGFkZGVkLXNldC1jb29raWU",
    "SameSite=Lax",
    "==",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const retained of [
    "X-Auth-Diagnostic: keep-auth-boundary",
    "X-Proxy-Diagnostic: keep-proxy-boundary",
    "X-Cookie-Diagnostic: keep-cookie-boundary",
    "X-Set-Cookie-Diagnostic: keep-set-cookie-boundary",
    "status=200 keep-final-boundary",
  ]) {
    expect(redacted).toContain(retained);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(8);
});

test("cookie folds preserve explicit diagnostics and fail closed on ambiguous assignments", () => {
  const input = [
    "Cookie: session=compact-cookie-secret\r",
    " status=429\r",
    " detail=compact cookie diagnostic\r",
    " X-Request-ID: keep-cookie-adjacent\r",
    "Set-Cookie: sid=compact-set-cookie-secret",
    " stack=Error",
    " message=compact set-cookie diagnostic",
    " X-Trace-ID: keep-set-cookie-adjacent",
    "Cookie: session=spaced-cookie-secret",
    " diagnostic_code = E_COOKIE",
    "Set-Cookie: sid=spaced-set-cookie-secret",
    " upstream_result = rejected",
    "completed=true",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "compact-cookie-secret",
    "compact-set-cookie-secret",
    "spaced-cookie-secret",
    "spaced-set-cookie-secret",
    "diagnostic_code = E_COOKIE",
    "upstream_result = rejected",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const retained of [
    "status=429",
    "detail=compact cookie diagnostic",
    "X-Request-ID: keep-cookie-adjacent",
    "stack=Error",
    "message=compact set-cookie diagnostic",
    "X-Trace-ID: keep-set-cookie-adjacent",
    "completed=true",
  ]) {
    expect(redacted).toContain(retained);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("quoted credential values remain sensitive across every supported folded line ending", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const input = [
      `Authorization: Digest username="auth-alpha${lineEnding} auth-beta", realm="auth-realm"`,
      `Proxy-Authorization: Custom vendor="proxy-alpha${lineEnding}\tproxy-beta", extension=proxy-tail`,
      `Cookie: session="cookie-alpha${lineEnding} cookie-beta"; theme=night`,
      `Set-Cookie: sid="set-alpha${lineEnding}\tset-beta"; Path=/; HttpOnly`,
      "status=401 keep-status",
      "message=keep-message",
    ].join(lineEnding);

    const redacted = redactText(input);

    for (const secret of [
      "auth-alpha",
      "auth-beta",
      "auth-realm",
      "proxy-alpha",
      "proxy-beta",
      "proxy-tail",
      "cookie-alpha",
      "cookie-beta",
      "theme=night",
      "set-alpha",
      "set-beta",
      "Path=/",
    ]) {
      expect(redacted).not.toContain(secret);
    }
    expect(redacted).toContain("status=401 keep-status");
    expect(redacted).toContain("message=keep-message");
    expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
  }
});

test("arbitrary extension auth parameters stay redacted while explicit diagnostics reset state", () => {
  const input = [
    "Authorization: Custom foo=alpha,",
    " extparam=beta,",
    ' vendor_thing="gamma",',
    " x-next=delta",
    " x-without-separator=epsilon",
    " stack=Error: independent authorization failure",
    " detail=provider rejected the independent request",
    " status=403 keep-status",
    " message=keep-message",
    "Proxy-Authorization: Custom first=proxy-alpha",
    " , second=proxy-beta",
    " , third=proxy-gamma",
    " status=407 keep-proxy-status",
    "Cookie: first=cookie-alpha;",
    " arbitrary_cookie=cookie-beta;",
    " another_cookie=cookie-gamma",
    " no_separator_cookie=cookie-delta",
    " detail=independent cookie diagnostic",
    "Set-Cookie: sid=set-alpha;",
    " VendorFlag=set-beta;",
    " VendorMode=set-gamma",
    " no_separator_set_cookie=set-delta",
    " message=independent set-cookie diagnostic",
    "X-Request-ID: keep-adjacent-header",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "foo=alpha",
    "extparam=beta",
    "vendor_thing",
    "gamma",
    "x-next=delta",
    "x-without-separator=epsilon",
    "first=proxy-alpha",
    "second=proxy-beta",
    "third=proxy-gamma",
    "first=cookie-alpha",
    "arbitrary_cookie=cookie-beta",
    "another_cookie=cookie-gamma",
    "no_separator_cookie=cookie-delta",
    "sid=set-alpha",
    "VendorFlag=set-beta",
    "VendorMode=set-gamma",
    "no_separator_set_cookie=set-delta",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "stack=Error: independent authorization failure",
    "detail=provider rejected the independent request",
    "status=403 keep-status",
    "message=keep-message",
    "status=407 keep-proxy-status",
    "detail=independent cookie diagnostic",
    "message=independent set-cookie diagnostic",
    "X-Request-ID: keep-adjacent-header",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("malformed quoted folds fail closed and later records start with clean state", () => {
  const input = [
    'Authorization: Digest username="unterminated-alpha',
    " hidden-auth-continuation",
    "status=401 independent-status",
    "Cookie: session=visible-cookie-secret;",
    " next=hidden-cookie-continuation",
    "stack=Error independent-cookie-stack",
    "Authorization: Basic final-auth-secret",
    "detail=final independent detail",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "unterminated-alpha",
    "hidden-auth-continuation",
    "visible-cookie-secret",
    "hidden-cookie-continuation",
    "final-auth-secret",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "status=401 independent-status",
    "stack=Error independent-cookie-stack",
    "detail=final independent detail",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(3);
});

test("large folded credential records are redacted in bounded linear time", () => {
  const folded = Array.from(
    { length: 12_000 },
    (_, index) => ` vendor-${index}=credential-fragment-${index},`,
  );
  const input = [
    "Authorization: Custom seed=credential-seed,",
    ...folded,
    " final-extension=credential-tail",
    "status=429 keep-after-large-record",
  ].join("\n");

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("credential-seed");
  expect(redacted).not.toContain("credential-fragment-11999");
  expect(redacted).not.toContain("credential-tail");
  expect(redacted).toContain("status=429 keep-after-large-record");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(1);
  expect(elapsedMs).toBeLessThan(1_500);
});

test("escaped quotes, controls, and Unicode fragments fail closed inside credential folds", () => {
  const input = [
    'Authorization: Digest username="escaped-alpha\\"quoted',
    ' unicode-auth-\u0001秘密", vendor=auth-tail',
    "Proxy-Authorization: Basic proxy-prefix-",
    " \u0002proxy-秘密-tail",
    'Cookie: session="escaped-cookie\\"quoted',
    ' unicode-cookie-\u0003秘密"; theme=night',
    "Set-Cookie: sid=set-prefix-",
    " \u0004set-秘密-tail; Path=/",
    "status=401 keep-status",
    "stack=Error: keep-stack",
  ].join("\r\n");

  const redacted = redactText(input);

  for (const secret of [
    "escaped-alpha",
    "unicode-auth",
    "auth-tail",
    "proxy-prefix",
    "proxy-秘密-tail",
    "escaped-cookie",
    "unicode-cookie",
    "theme=night",
    "set-prefix",
    "set-秘密-tail",
    "Path=/",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("status=401 keep-status");
  expect(redacted).toContain("stack=Error: keep-stack");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});

test("diagnostic-named parameters remain sensitive when separators keep them inside a credential record", () => {
  const input = [
    "Authorization: Custom seed=auth-seed,",
    " message=auth-message,",
    " detail=auth-detail",
    " status=403 independent-status",
    "Cookie: sid=cookie-seed;",
    " message=cookie-message;",
    " detail=cookie-detail",
    " stack=Error independent-stack",
    "X-Trace-ID: keep-final-boundary",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "auth-seed",
    "auth-message",
    "auth-detail",
    "cookie-seed",
    "cookie-message",
    "cookie-detail",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("status=403 independent-status");
  expect(redacted).toContain("stack=Error independent-stack");
  expect(redacted).toContain("X-Trace-ID: keep-final-boundary");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(2);
});

test("empty sensitive headers fail closed on malformed and extension continuations", () => {
  const input = [
    "Authorization:",
    " Basic",
    " split-auth-secret",
    " status=401 keep-auth-status",
    "Proxy-Authorization:",
    " extension=proxy-secret",
    " stack=Error keep-proxy-stack",
    "Cookie:",
    " opaque-cookie-secret",
    " message=keep-cookie-message",
    "Set-Cookie:",
    " vendor-set-cookie-secret",
    " detail=keep-set-cookie-detail",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of [
    "split-auth-secret",
    "proxy-secret",
    "opaque-cookie-secret",
    "vendor-set-cookie-secret",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  for (const diagnostic of [
    "status=401 keep-auth-status",
    "stack=Error keep-proxy-stack",
    "message=keep-cookie-message",
    "detail=keep-set-cookie-detail",
  ]) {
    expect(redacted).toContain(diagnostic);
  }
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
});
