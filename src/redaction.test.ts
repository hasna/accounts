import { expect, test } from "bun:test";
import {
  isSensitiveCredentialKey,
  redactArgv,
  redactPublicValue,
  redactText,
} from "./lib/redaction.js";

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

test("semantic credential-key normalization covers separator and camel-case variants without near misses", () => {
  const sensitive = [
    "oauth_token",
    "oauth.key",
    "oauth key",
    "oauthKey",
    "bearerKey",
    "sessionKey",
    "bearer-token",
    "passphrase",
    "signing_secret",
    "consumerSecret",
    "database_password",
    "webhookCredential",
    "apikey",
    "clientsecret",
    "oauthtoken",
    "consumersecret",
    "databasepassword",
    "webhookcredential",
    "auth",
    "secret-key",
    "service-account-key",
    "auth-header",
    "service-auth",
    "bearer",
    "credentials",
    "encryption-key",
    "master-key",
    "client-key",
    "aws-access-key-id",
  ];
  const benign = [
    "oauth_scope",
    "bearer_mode",
    "signature_algorithm",
    "consumerProfile",
    "database_passwordless",
    "webhookCredentialProvider",
    "tokenBucket",
    "secretariat",
    "monkey",
    "bearer-mode",
    "credential-provider",
    "service-account",
    "authorization-policy",
    "keyboard",
    "keynote",
    "monkey",
    "hockey",
    "turkey",
  ];

  for (const key of sensitive) expect(isSensitiveCredentialKey(key), key).toBe(true);
  for (const key of benign) expect(isSensitiveCredentialKey(key), key).toBe(false);

  const generatedQualifiers = [
    "backup",
    "cache",
    "custom",
    "database",
    "device",
    "encryption",
    "ephemeral",
    "identity",
    "integration",
    "master",
    "organization",
    "project",
    "provider",
    "recovery",
    "runtime",
    "tenant",
    "workspace",
  ];
  for (const qualifier of generatedQualifiers) {
    for (const key of [
      `${qualifier}-key`,
      `${qualifier}_key`,
      `${qualifier} key`,
      `${qualifier}Key`,
      `key-${qualifier}`,
      `${qualifier}-key-id`,
    ]) {
      expect(isSensitiveCredentialKey(key), key).toBe(true);
    }
  }

  const rawSecrets = sensitive.map((key, index) => `${key}=normalized-raw-${index}`);
  const jsonSecrets = Object.fromEntries(
    sensitive.map((key, index) => [key, `normalized-json-${index}`]),
  );
  const redacted = redactText(`${rawSecrets.join("\n")}\n${JSON.stringify(jsonSecrets)}`);

  for (let index = 0; index < sensitive.length; index++) {
    expect(redacted).not.toContain(`normalized-raw-${index}`);
    expect(redacted).not.toContain(`normalized-json-${index}`);
  }

  const benignInput = benign.map((key, index) => `${key}=benign-${index}`).join("\n");
  expect(redactText(benignInput)).toBe(benignInput);
});

test("valid nested JSON recursively redacts decoded credential keys", () => {
  const input = String.raw`{
    "outer": {
      "Authoriz\u0061tion": "escaped-auth-secret",
      "nested": [
        {"x-\u0061pi-key": "escaped-api-secret"},
        {"consumer\u0053ecret": "escaped-consumer-secret"}
      ]
    },
    "status": 401,
    "message": "keep-json-diagnostic",
    "providerError": "Authorization: Bearer nested-json-header-secret"
  }`;

  const redacted = redactText(input);

  for (const secret of [
    "escaped-auth-secret",
    "escaped-api-secret",
    "escaped-consumer-secret",
    "nested-json-header-secret",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  const parsed = JSON.parse(redacted) as {
    outer: { Authorization: string; nested: Array<Record<string, string>> };
    status: number;
    message: string;
    providerError: string;
  };
  expect(parsed.outer.Authorization).toBe("[REDACTED]");
  expect(parsed.outer.nested[0]?.["x-api-key"]).toBe("[REDACTED]");
  expect(parsed.outer.nested[1]?.consumerSecret).toBe("[REDACTED]");
  expect(parsed.providerError).toContain("[REDACTED]");
  expect(redacted).toContain("[REDACTED]");
  expect(redacted).toContain('"status":401');
  expect(redacted).toContain('"message":"keep-json-diagnostic"');
});

test("escaped serialized credential keys fail closed across malformed sibling and fused-tail fragments", () => {
  const samples: Array<(secret: string) => string> = [
    (secret) => String.raw`{"Authoriz\u0061tion":"${secret}","status" 401}`,
    (secret) => String.raw`{"Authoriz\u0061tion":"${secret}","status":}`,
    (secret) => String.raw`{"x-\u0061pi-key":"${secret}","message"="denied"}`,
    (secret) => String.raw`{"x-\u0061pi-key":"${secret}",message:"denied"}`,
    (secret) => String.raw`{"consumer\u0053ecret":"${secret}"}fused=tail`,
    (secret) => String.raw`{"database\u005fpassword":"${secret}","detail":"ok"`,
    (secret) => String.raw`{"oauth\u005ftoken":"${secret}",,"status":401}`,
    (secret) => String.raw`{"webhook\u0043redential":"${secret}";"status":401}`,
  ];

  for (const [index, render] of samples.entries()) {
    const input = render(`escaped-fragment-${index}`);
    const redacted = redactText(input);
    expect(redacted, input).not.toContain(`escaped-fragment-${index}`);
    expect(redacted, input).toContain("[REDACTED]");
  }
});

test("argument redaction uses the same semantic credential-key classifier", () => {
  const redacted = redactArgv([
    "provider",
    "--oauth_token",
    "argv-oauth-secret",
    "--passphrase",
    "argv-passphrase-secret",
    "--api-key:argv-colon-secret",
    "-k",
    "argv-short-secret",
    "-kargv-joined-secret",
    "--consumerSecret=argv-consumer-secret",
    "--tokenBucket",
    "keep-token-bucket",
    "--webhookCredential",
    "argv-webhook-secret",
  ]);

  expect(redacted).toEqual([
    "provider",
    "--oauth_token",
    "[REDACTED]",
    "--passphrase",
    "[REDACTED]",
    "--api-key:[REDACTED]",
    "-k",
    "[REDACTED]",
    "-k[REDACTED]",
    "--consumerSecret=[REDACTED]",
    "--tokenBucket",
    "keep-token-bucket",
    "--webhookCredential",
    "[REDACTED]",
  ]);
});

test("argument redaction fails closed on combined and Unicode credential short options", () => {
  const secrets = [
    "argv-secret-key",
    "argv-service-account",
    "argv-auth-header",
    "argv-service-auth",
    "argv-bearer",
    "argv-credentials",
    "argv-vk",
    "argv-vvk",
    "argv-fullwidth-k",
    "argv-unicode-minus-k",
    "argv-cluster-attached",
  ];
  const redacted = redactArgv([
    "provider",
    "--secret-key",
    secrets[0]!,
    `--service-account-key=${secrets[1]}`,
    `--auth-header:${secrets[2]}`,
    "--service-auth",
    secrets[3]!,
    "--bearer",
    secrets[4]!,
    "--credentials",
    secrets[5]!,
    "-vk",
    secrets[6]!,
    "-vvk",
    secrets[7]!,
    "－ｋ",
    secrets[8]!,
    "−k",
    secrets[9]!,
    `-vk${secrets[10]}`,
    "--bearer-mode",
    "keep-bearer-mode",
  ]);

  const output = JSON.stringify(redacted);
  for (const secret of secrets) expect(output).not.toContain(secret);
  expect(redacted.at(-1)).toBe("keep-bearer-mode");
});

test("argument redaction reclassifies chained sensitive options while awaiting a value", () => {
  expect(
    redactArgv([
      "claude",
      "--api-key",
      "--client-key",
      "chained-client-secret",
      "--api-key",
      "--api-key",
      "repeated-api-secret",
      "-k",
      "-vk",
      "clustered-short-secret",
      "--api-key",
      "--master-key=attached-master-secret",
      "keep-after-attached-option",
      "--api-key",
      '"--client-key"',
      "keep-after-quoted-value",
      "--api-key",
      "-not-a-credential-option",
      "keep-after-dash-leading-value",
      "--api-key",
      "client-key",
      "keep-after-unprefixed-value",
    ]),
  ).toEqual([
    "claude",
    "--api-key",
    "--client-key",
    "[REDACTED]",
    "--api-key",
    "--api-key",
    "[REDACTED]",
    "-k",
    "-vk",
    "[REDACTED]",
    "--api-key",
    "--master-key=[REDACTED]",
    "keep-after-attached-option",
    "--api-key",
    "[REDACTED]",
    "keep-after-quoted-value",
    "--api-key",
    "[REDACTED]",
    "keep-after-dash-leading-value",
    "--api-key",
    "[REDACTED]",
    "keep-after-unprefixed-value",
  ]);
});

test("argument redaction keeps credential-shaped opaque tokens bound to pending options", () => {
  for (const value of [
    "-x=client-key=opaque-bound-secret",
    "--label/client-key/opaque-bound-secret",
    "-x<client-key<opaque-bound-secret",
    "--wrapper{client-key:opaque-bound-secret}",
    "－x=client-key=opaque-bound-secret",
  ]) {
    expect(
      redactArgv([
        "provider",
        "--api-key",
        value,
        "keep-after-opaque-bound-value",
      ]),
    ).toEqual([
      "provider",
      "--api-key",
      "[REDACTED]",
      "keep-after-opaque-bound-value",
    ]);
  }
});

test("argument redaction treats malformed bare-option grammar as one opaque pending value", () => {
  const variants = [
    (secret: string) => "-",
    (secret: string) => "---",
    (secret: string) => "----",
    (secret: string) => "--.",
    (secret: string) => "--_",
    (secret: string) => "-.",
    (secret: string) => "-_",
    (secret: string) => `---api-key=${secret}`,
    (secret: string) => `----client-key:${secret}`,
    (secret: string) => `--.master-key=${secret}`,
    (secret: string) => `--_access-key-id:${secret}`,
    (secret: string) => `-.api-key=${secret}`,
    (secret: string) => `-_client-key:${secret}`,
    (secret: string) => `－－－api-key=${secret}`,
    (secret: string) => `−−−client-key:${secret}`,
  ];

  for (const [index, render] of variants.entries()) {
    const secret = `argv-malformed-option-secret-${index}`;
    expect(
      redactArgv([
        "provider",
        "--api-key",
        render(secret),
        `keep-after-malformed-argv-${index}`,
      ]),
    ).toEqual([
      "provider",
      "--api-key",
      "[REDACTED]",
      `keep-after-malformed-argv-${index}`,
    ]);
  }
});

test("argument redaction preserves supported option grammar around credential chains", () => {
  expect(
    redactArgv([
      "provider",
      "--api-key",
      "--client.key",
      "dot-body-secret",
      "--api-key",
      "--client_key",
      "underscore-body-secret",
      "-k",
      "-vk",
      "cluster-secret",
      "-k",
      "-vvkattached-secret",
      "keep-after-attached-short",
      "－ｋ",
      "unicode-short-secret",
      "--verbose",
      "keep-verbose",
    ]),
  ).toEqual([
    "provider",
    "--api-key",
    "--client.key",
    "[REDACTED]",
    "--api-key",
    "--client_key",
    "[REDACTED]",
    "-k",
    "-vk",
    "[REDACTED]",
    "-k",
    "-vvk[REDACTED]",
    "keep-after-attached-short",
    "-k",
    "[REDACTED]",
    "--verbose",
    "keep-verbose",
  ]);
});

test("argument redaction honors exact end-of-options markers in ordinary and pending states", () => {
  const afterOrdinaryMarker = [
    "provider",
    "--",
    "--api-key",
    "keep-positional-api-value",
    "--client-key=keep-positional-attached-value",
    "-k",
    "keep-positional-short-value",
  ];
  expect(redactArgv(afterOrdinaryMarker)).toEqual(afterOrdinaryMarker);

  const afterPendingMarker = [
    "provider",
    "--api-key",
    "--",
    "--client-key",
    "keep-pending-marker-client-value",
    "--api-key=keep-pending-marker-attached-value",
    "-vk",
    "keep-pending-marker-short-value",
  ];
  expect(redactArgv(afterPendingMarker)).toEqual(afterPendingMarker);
});

test("argument end-of-options preservation stays linear across large positional payloads", () => {
  const positional = Array.from(
    { length: 200_000 },
    (_, index) => index % 2 === 0
      ? `--api-key=keep-positional-${index}`
      : `-k-keep-positional-${index}`,
  );
  const input = ["provider", "--api-key", "--", ...positional];

  const startedAt = performance.now();
  const redacted = redactArgv(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).toEqual(input);
  expect(elapsedMs).toBeLessThan(1_500);
});

test("captured command end-of-options requires one exact raw ASCII token", () => {
  const normalizedDashes = [
    "\u2010",
    "\u2011",
    "\u2012",
    "\u2013",
    "\u2014",
    "\u2015",
    "\u2212",
    "\uFE58",
    "\uFE63",
    "\uFF0D",
  ];
  const falseMarkers = [
    ...normalizedDashes.map((dash) => `${dash}${dash}`),
    '"--"',
    "'--'",
    "\\--",
    "\\-\\-",
    "(--)",
    "[--]",
    "{--}",
    "<-->",
    "x|--",
    "x/--",
    "x:--",
  ];

  for (const [markerIndex, marker] of falseMarkers.entries()) {
    const ordinarySecret = `argv-false-marker-ordinary-${markerIndex}-secret`;
    const ordinaryRetained = `keep-argv-false-marker-ordinary-${markerIndex}`;
    const ordinary = redactArgv([
      "provider",
      marker,
      `--client-key=${ordinarySecret}`,
      "--trace",
      ordinaryRetained,
    ]);
    expect(ordinary.join(" ")).not.toContain(ordinarySecret);
    expect(ordinary).toContain(ordinaryRetained);

    const pendingSecret = `argv-false-marker-pending-${markerIndex}-secret`;
    const pendingRetained = `keep-argv-false-marker-pending-${markerIndex}`;
    const pending = redactArgv([
      "provider",
      "--api-key",
      marker,
      `--client-key=${pendingSecret}`,
      "--trace",
      pendingRetained,
    ]);
    expect(pending.join(" ")).not.toContain(pendingSecret);
    expect(pending).toContain(pendingRetained);
  }

  for (const [lineIndex, lineEnding] of ["\n", "\r\n", "\r"].entries()) {
    for (const [markerIndex, marker] of falseMarkers.entries()) {
      for (const context of ["ordinary", "pending", "active"] as const) {
        const secret =
          `false-marker-${context}-${lineIndex}-${markerIndex}-secret`;
        const retained =
          `keep-false-marker-${context}-${lineIndex}-${markerIndex}`;
        const input = context === "ordinary"
          ? `provider${lineEnding}${marker} --client-key=${secret} --trace ${retained}`
          : context === "pending"
            ? `provider --api-key${lineEnding}${marker} --client-key=${secret} --trace ${retained}`
            : `provider --api-key seed\\${lineEnding}tail/${marker} --client-key=${secret} --trace ${retained}`;
        const redacted = redactText(input);

        expect(redacted, input).not.toContain(secret);
        expect(redacted, input).toContain(`--trace ${retained}`);
      }
    }

    const ordinarySentinel =
      `provider${lineEnding}-- --api-key keep-ordinary-${lineIndex}`;
    expect(redactText(ordinarySentinel)).toBe(ordinarySentinel);

    const pendingSentinel =
      `provider --api-key${lineEnding}-- --client-key keep-pending-${lineIndex}`;
    expect(redactText(pendingSentinel)).toBe(pendingSentinel);
  }
});

test("command-text chained sensitive options preserve pending state across line endings", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const secret = `command-chained-secret-${lineEnding.length}`;
    const input = [
      "provider --api-key",
      "--client-key",
      secret,
      "status=keep-command-chain-status",
    ].join(lineEnding);

    const redacted = redactText(input);

    expect(redacted).not.toContain(secret);
    expect(redacted).toContain("--api-key");
    expect(redacted).toContain("--client-key");
    expect(redacted).toContain("status=keep-command-chain-status");
  }
});

test("command-text pending options keep opaque dash-leading values bound across syntax variants", () => {
  const separators = [" ", "\n", "\r\n", "\r"];
  const variants = [
    (secret: string) => `--label/client-key/${secret}`,
    (secret: string) => `"--label/client-key/${secret}"`,
    (secret: string) => `\\--label/client-key/${secret}`,
    (secret: string) => `－label/client-key/${secret}`,
    (secret: string) => `(--label/client-key/${secret})`,
    (secret: string) => `|--label/client-key/${secret}`,
  ];

  for (const [separatorIndex, separator] of separators.entries()) {
    for (const [variantIndex, render] of variants.entries()) {
      const secret = `opaque-command-bound-${separatorIndex}-${variantIndex}`;
      const retained = `status=keep-opaque-command-${separatorIndex}-${variantIndex}`;
      const input = `provider --api-key${separator}${render(secret)} ${retained}`;
      const redacted = redactText(input);

      expect(redacted, input).not.toContain(secret);
      expect(redacted, input).toContain("[REDACTED]");
      expect(redacted, input).toContain(retained);
    }
  }
});

test("command-text pending values reject malformed bare-option grammar across line endings", () => {
  const variants = [
    (secret: string) => "-",
    (secret: string) => "---",
    (secret: string) => "----",
    (secret: string) => "--.",
    (secret: string) => "--_",
    (secret: string) => "-.",
    (secret: string) => "-_",
    (secret: string) => `---api-key=${secret}`,
    (secret: string) => `----client-key:${secret}`,
    (secret: string) => `--.master-key=${secret}`,
    (secret: string) => `--_access-key-id:${secret}`,
    (secret: string) => `-.k=${secret}`,
    (secret: string) => `-_k:${secret}`,
    (secret: string) => `－－－api-key=${secret}`,
    (secret: string) => `−−−client-key:${secret}`,
  ];

  for (const [lineIndex, lineEnding] of [" ", "\n", "\r\n", "\r"].entries()) {
    for (const [variantIndex, render] of variants.entries()) {
      const secret = `command-malformed-option-secret-${lineIndex}-${variantIndex}`;
      const retained =
        `status=keep-after-malformed-command-${lineIndex}-${variantIndex}`;
      const malformed = render(secret);
      const redacted = redactText(
        `provider --api-key${lineEnding}${malformed} ${retained}`,
      );

      expect(redacted, malformed).not.toContain(secret);
      expect(redacted, malformed).toBe(
        `provider --api-key${lineEnding}[REDACTED] ${retained}`,
      );
    }
  }
});

test("standalone malformed attached credentials stay fail-closed without erasing safe tokens", () => {
  const variants = [
    (secret: string) => `---api-key=${secret}`,
    (secret: string) => `----client-key:${secret}`,
    (secret: string) => `--.master-key=${secret}`,
    (secret: string) => `--_access-key-id:${secret}`,
    (secret: string) => `-.api-key=${secret}`,
    (secret: string) => `-_client-key:${secret}`,
    (secret: string) => `－－－api-key=${secret}`,
    (secret: string) => `−−−client-key:${secret}`,
  ];

  for (const [index, render] of variants.entries()) {
    const secret = `standalone-malformed-attached-secret-${index}`;
    const retained = `status=keep-standalone-malformed-${index}`;
    const redacted = redactText(`provider ${render(secret)} ${retained}`);

    expect(redacted).not.toContain(secret);
    expect(redacted).toContain("[REDACTED]");
    expect(redacted).toContain(retained);
  }
});

test("command-text pending options classify complete opaque tokens before punctuation", () => {
  const separators = [" ", "\n", "\r\n", "\r"];
  const variants = [
    (secret: string) => `--label=opaque/--label=${secret}`,
    (secret: string) => `--label=opaque|--label=${secret}`,
    (secret: string) => `--label=opaque<--label=${secret}`,
    (secret: string) => `(--label=opaque/--label=${secret})`,
    (secret: string) => `－label=opaque/－label=${secret}`,
    (secret: string) => `"--label=opaque/--label=${secret}"`,
    (secret: string) => `\\--label=opaque/--label=${secret}`,
  ];

  for (const [separatorIndex, separator] of separators.entries()) {
    for (const [variantIndex, render] of variants.entries()) {
      const secret = `complete-token-hidden-${separatorIndex}-${variantIndex}`;
      const retained = `status=keep-complete-token-${separatorIndex}-${variantIndex}`;
      const input = `provider --api-key${separator}${render(secret)} ${retained}`;
      const redacted = redactText(input);

      expect(redacted, input).not.toContain(secret);
      expect(redacted, input).toContain("[REDACTED]");
      expect(redacted, input).toContain(retained);
    }
  }

  for (const [separator, syntax] of [
    ["=", "--client-key=[REDACTED]"],
    [":", "--client-key:[REDACTED]"],
  ]) {
    const attachedReplacement =
      `provider --api-key --client-key${separator}complete-attached-secret ` +
      "status=keep-attached-replacement";
    const attachedRedacted = redactText(attachedReplacement);
    expect(attachedRedacted).not.toContain("complete-attached-secret");
    expect(attachedRedacted).toContain(syntax);
    expect(attachedRedacted).toContain("status=keep-attached-replacement");
  }

  for (const separator of ["=", ":"]) {
    const secret = `complete-attached-value${separator}hidden`;
    const input =
      `provider --api-key --client-key${separator}opaque/--label=${secret} ` +
      "status=keep-attached-complete-token";
    const redacted = redactText(input);
    expect(redacted).not.toContain(secret);
    expect(redacted).toContain("[REDACTED]");
    expect(redacted).toContain("status=keep-attached-complete-token");
  }

  const nearMiss =
    "provider --label=opaque/--label=VISIBLE status=keep-non-sensitive-near-miss";
  expect(redactText(nearMiss)).toBe(nearMiss);
});

test("command-text attached option-looking values redact in place without swallowing safe tokens", () => {
  const cases = [
    {
      input: "provider --api-key=--client-key status=keep-attached-equals",
      secret: "--client-key",
      retained: "status=keep-attached-equals",
      syntax: "--api-key=[REDACTED]",
    },
    {
      input: "provider --api-key:--client-key status=keep-attached-colon",
      secret: "--client-key",
      retained: "status=keep-attached-colon",
      syntax: "--api-key:[REDACTED]",
    },
    {
      input: 'provider --api-key="--client-key" status=keep-attached-quoted',
      secret: "--client-key",
      retained: "status=keep-attached-quoted",
      syntax: "--api-key=[REDACTED]",
    },
    {
      input: "provider --api-key=－client-key status=keep-attached-unicode",
      secret: "－client-key",
      retained: "status=keep-attached-unicode",
      syntax: "--api-key=[REDACTED]",
    },
    {
      input:
        "diagnostic|--api-key=--client-key|--trace keep-attached-punctuation",
      secret: "--client-key",
      retained: "|--trace keep-attached-punctuation",
      syntax: "--api-key=[REDACTED]",
    },
    {
      input:
        "diagnostic/--api-key:--client-key/--trace keep-attached-slash",
      secret: "--client-key",
      retained: "/--trace keep-attached-slash",
      syntax: "--api-key:[REDACTED]",
    },
  ];

  for (const sample of cases) {
    const redacted = redactText(sample.input);
    expect(redacted, sample.input).not.toContain(sample.secret);
    expect(redacted, sample.input).toContain(sample.syntax);
    expect(redacted, sample.input).toContain(sample.retained);
  }
});

test("pending opaque dash-leading command values stay linear with dense separators", () => {
  const secret =
    `--label=opaque${"/--label=segment".repeat(36_000)}` +
    "/--label=terminal-hidden-value";
  const input = `provider --api-key ${secret} status=keep-dense-opaque`;
  expect(input.length).toBeGreaterThan(512 * 1024);

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("terminal-hidden-value");
  expect(redacted).toContain("status=keep-dense-opaque");
  expect(elapsedMs).toBeLessThan(1_500);
});

test("command-text redaction shares argv option grammar across quoting and boundaries", () => {
  const secrets = [
    "command-api-secret",
    "command-secret-key-secret",
    "command-service-auth secret",
    "command-credentials escaped",
    "command-short-secret",
    "command-cluster-secret",
    "command-attached-cluster-secret",
    "command-encryption-secret",
    "command-master-secret",
    "command-client-secret",
    "command-access-key-id-secret",
    "command-repeated-api-secret",
    "command-repeated-client-secret",
    "command-wrapped-secret",
    "command-punctuation-secret",
    "command escaped quoted secret",
    "command-attached-punctuation-secret",
    "command-escaped-semicolon-secret",
    "command-quoted-semicolon-secret",
  ];
  const input = [
    `provider --api-key ${secrets[0]} --verbose keep-verbose`,
    `provider "--secret-key=${secrets[1]}" status=keep-quoted-status`,
    `provider --service-auth '${secrets[2]}' --mode keep-mode`,
    `provider --credentials command-credentials\\ escaped --trace keep-trace`,
    `provider -k ${secrets[4]} --color keep-color`,
    `provider -vk ${secrets[5]} --diagnostic keep-cluster-diagnostic`,
    `provider -vvk${secrets[6]} --format keep-format`,
    `provider --encryption-key "${secrets[7]}" --keep encryption-diagnostic`,
    `provider --master-key=${secrets[8]} --keep master-diagnostic`,
    `provider --client-key:${secrets[9]} --keep client-diagnostic`,
    `provider --aws-access-key-id ${secrets[10]} --region keep-region`,
    `provider --api-key ${secrets[11]} --client-key ${secrets[12]} --keep repeated-diagnostic`,
    `cmd="provider --api-key ${secrets[13]} --verbose keep-wrapped-diagnostic"`,
    `error:--api-key ${secrets[14]} --verbose keep-punctuation-diagnostic`,
    `cmd='provider --client-key \\"${secrets[15]}\\" --mode keep-escaped-quote-mode'`,
    `error:--master-key=${secrets[16]};status=keep-attached-punctuation`,
    `provider --api-key=${secrets[17]}\\;escaped-tail-marker --keep escaped-semicolon-diagnostic`,
    `provider --client-key="${secrets[18]};quoted-tail-marker" --keep quoted-semicolon-diagnostic`,
    "provider --api-key --verbose keep-missing-value",
    "provider -- --api-key keep-after-end-of-options",
    "status=418 keep-final-command-diagnostic",
  ].join("\n");

  const redacted = redactText(input);

  for (const secret of secrets) expect(redacted).not.toContain(secret);
  for (const retained of [
    "--verbose keep-verbose",
    "status=keep-quoted-status",
    "--mode keep-mode",
    "--trace keep-trace",
    "--color keep-color",
    "--diagnostic keep-cluster-diagnostic",
    "--format keep-format",
    "--keep encryption-diagnostic",
    "--keep master-diagnostic",
    "--keep client-diagnostic",
    "--region keep-region",
    "--keep repeated-diagnostic",
    "--verbose keep-wrapped-diagnostic",
    "--verbose keep-punctuation-diagnostic",
    "--mode keep-escaped-quote-mode",
    "status=keep-attached-punctuation",
    "--keep escaped-semicolon-diagnostic",
    "--keep quoted-semicolon-diagnostic",
    "--api-key --verbose keep-missing-value",
    "-- --api-key keep-after-end-of-options",
    "status=418 keep-final-command-diagnostic",
  ]) {
    expect(redacted).toContain(retained);
  }
  expect(redacted).not.toContain("escaped-tail-marker");
  expect(redacted).not.toContain("quoted-tail-marker");
});

test("command-text pending credential values cross physical lines without swallowing records", () => {
  const lineEndings = ["\n", "\r\n", "\r"];

  for (const lineEnding of lineEndings) {
    const secrets = [
      "multiline-plain-secret",
      "--multiline-quoted-secret",
      "--multiline-escaped-quoted-secret",
      "--multiline-doubled-quote-secret",
      "--multiline-mixed-wrapper-secret",
      "--multiline-escaped-dash-secret",
      "--multiline-end-marker-secret",
      "multiline-repeated-option-secret",
    ];
    const input = [
      `provider --api-key${lineEnding}${secrets[0]}${lineEnding}status=keep-plain-status`,
      `provider --client-key${lineEnding}"${secrets[1]}"${lineEnding}message=keep-quoted-message`,
      `provider --master-key${lineEnding}\\"${secrets[2]}\\"${lineEnding}detail=keep-escaped-detail`,
      `provider --encryption-key${lineEnding}"${secrets[3]}""-tail"${lineEnding}stack=keep-doubled-stack`,
      `provider --service-account-key${lineEnding}(\\"${secrets[4]}\\")${lineEnding}status=keep-wrapper-status`,
      `provider --auth-header${lineEnding}\\${secrets[5]}${lineEnding}detail=keep-escaped-dash-detail`,
      `provider --credentials${lineEnding}"--"${secrets[6]}${lineEnding}message=keep-marker-message`,
      `provider --api-key${lineEnding}--client-key${lineEnding}${secrets[7]}${lineEnding}detail=keep-repeated-detail`,
      `provider --api-key${lineEnding}--verbose keep-missing-option${lineEnding}status=keep-missing-status`,
      `provider --api-key${lineEnding}(--verbose) keep-wrapped-missing-option${lineEnding}message=keep-wrapped-missing-message`,
      `provider --api-key${lineEnding}--${lineEnding}keep-after-unquoted-marker`,
      `provider --api-key${lineEnding}${lineEnding}keep-after-blank-record`,
    ].join(`${lineEnding}${lineEnding}`);

    const redacted = redactText(input);

    for (const secret of secrets) expect(redacted).not.toContain(secret);
    for (const retained of [
      "status=keep-plain-status",
      "message=keep-quoted-message",
      "detail=keep-escaped-detail",
      "stack=keep-doubled-stack",
      "status=keep-wrapper-status",
      "detail=keep-escaped-dash-detail",
      "message=keep-marker-message",
      "detail=keep-repeated-detail",
      "--verbose keep-missing-option",
      "status=keep-missing-status",
      "keep-wrapped-missing-option",
      "message=keep-wrapped-missing-message",
      "--",
      "keep-after-unquoted-marker",
      "keep-after-blank-record",
    ]) {
      expect(redacted).toContain(retained);
    }
    expect(redacted).not.toContain("(--verbose)");
  }
});

test("command-text option boundaries cover safe punctuation and reject embedded near-misses", () => {
  const safePrefixes = [
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
    ":",
    "=",
  ];
  const safeLines = safePrefixes.map(
    (prefix, index) =>
      `diagnostic${prefix}--api-key punctuation-secret-${index} --verbose keep-punctuation-${index}`,
  );
  const nearMisses = [
    "word--api-key keep-word-near-miss",
    "https://example.invalid/--api-key keep-url-near-miss",
    "https://example.invalid/－－api-key keep-unicode-url-near-miss",
    "www.example.invalid/--api-key keep-www-near-miss",
    "person@--api-key keep-email-near-miss",
    "person@example.invalid/--api-key keep-email-path-near-miss",
    "1--api-key keep-arithmetic-near-miss",
    "1/--api-key keep-division-near-miss",
    "1<--api-key keep-less-than-near-miss",
    "1>--api-key keep-greater-than-near-miss",
    "(1)/--api-key keep-parenthesized-division-near-miss",
    "(1)<--api-key keep-parenthesized-less-than-near-miss",
    "(1)>--api-key keep-parenthesized-greater-than-near-miss",
    "left+--api-key keep-plus-near-miss",
    "left*--api-key keep-times-near-miss",
  ];

  const redacted = redactText([...safeLines, ...nearMisses].join("\n"));

  for (let index = 0; index < safePrefixes.length; index++) {
    expect(redacted).not.toContain(`punctuation-secret-${index}`);
    expect(redacted).toContain(`--verbose keep-punctuation-${index}`);
  }
  for (const nearMiss of nearMisses) expect(redacted).toContain(nearMiss);
});

test("logical command values remain redacted across escaped and quoted newlines", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const secrets = [
      "bare-continuation-secret",
      "fragment-continuation-secret",
      "quoted-continuation-secret",
    ];
    const input = [
      `provider --api-key \\${lineEnding}${secrets[0]}${lineEnding}status=keep-bare-continuation`,
      `provider --client-key first-fragment\\${lineEnding}${secrets[1]}${lineEnding}message=keep-fragment-continuation`,
      `provider --master-key "quoted-first-fragment${lineEnding}${secrets[2]}"${lineEnding}detail=keep-quoted-continuation`,
      `provider --api-key \\${lineEnding}--verbose keep-missing-after-continuation${lineEnding}stack=keep-missing-continuation`,
    ].join(`${lineEnding}${lineEnding}`);

    const redacted = redactText(input);

    for (const secret of secrets) expect(redacted).not.toContain(secret);
    for (const retained of [
      "status=keep-bare-continuation",
      "message=keep-fragment-continuation",
      "detail=keep-quoted-continuation",
      "--verbose keep-missing-after-continuation",
      "stack=keep-missing-continuation",
    ]) {
      expect(redacted).toContain(retained);
    }
  }
});

test("active logical values consume continuation suffixes without re-entering option parsing", () => {
  const starts = [
    { label: "separate", value: "--api-key seed\\" },
    { label: "attached", value: "--client-key=seed\\" },
    { label: "colon", value: "--master-key:seed\\" },
    { label: "short", value: "-kseed\\" },
  ];
  const suffixes = [
    (secret: string) => `tail/--label=${secret}`,
    (secret: string) => `tail|--label:${secret}`,
    (secret: string) => `tail<--label=opaque:${secret}`,
    (secret: string) => `tail(--label=opaque=${secret})`,
    (secret: string) => `tail((/|<--label:opaque=${secret}>))`,
    (secret: string) => `tail/－－label=opaque:${secret}`,
  ];

  for (const [lineEndingIndex, lineEnding] of ["\n", "\r\n", "\r"].entries()) {
    for (const start of starts) {
      for (const [suffixIndex, renderSuffix] of suffixes.entries()) {
        const secret =
          `active-${start.label}-${lineEndingIndex}-${suffixIndex}-suffix-secret`;
        const followingSecret =
          `active-${start.label}-${lineEndingIndex}-${suffixIndex}-following-secret`;
        const retained =
          `keep-active-${start.label}-${lineEndingIndex}-${suffixIndex}`;
        const input =
          `provider ${start.value}${lineEnding}${renderSuffix(secret)} ` +
          `--client-key=${followingSecret} --trace ${retained}`;
        const redacted = redactText(input);

        expect(redacted, input).not.toContain(secret);
        expect(redacted, input).not.toContain(followingSecret);
        expect(redacted, input).toContain(`--trace ${retained}`);
      }
    }
  }
});

test("active quoted logical values consume closure suffixes through whitespace", () => {
  const starts = [
    {
      label: "separate-double",
      value: '--api-key "seed',
      close: (suffix: string) => `tail"${suffix}`,
    },
    {
      label: "attached-single",
      value: "--client-key='seed",
      close: (suffix: string) => `tail'${suffix}`,
    },
    {
      label: "short-escaped-double",
      value: '-k"seed',
      close: (suffix: string) => `tail\\"quoted"${suffix}`,
    },
  ];

  for (const [lineEndingIndex, lineEnding] of ["\n", "\r\n", "\r"].entries()) {
    for (const start of starts) {
      const suffixSecret =
        `quoted-${start.label}-${lineEndingIndex}-suffix-secret`;
      const followingSecret =
        `quoted-${start.label}-${lineEndingIndex}-following-secret`;
      const retained = `keep-quoted-${start.label}-${lineEndingIndex}`;
      const input =
        `provider ${start.value}${lineEnding}` +
        start.close(
          `/--${lineEnding === "\r" ? "label:" : "label="}${suffixSecret}`,
        ) +
        " " +
        `--client-key=${followingSecret} --trace ${retained}`;
      const redacted = redactText(input);

      expect(redacted, input).not.toContain(suffixSecret);
      expect(redacted, input).not.toContain(followingSecret);
      expect(redacted, input).toContain(`--trace ${retained}`);
    }
  }
});

test("active logical values keep embedded end markers and option names as value data", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const escapedFollowing = `escaped-marker-following-${lineEnding.length}-secret`;
    const quotedFollowing = `quoted-marker-following-${lineEnding.length}-secret`;
    const input = [
      `provider --api-key seed\\${lineEnding}tail/-- --client-key=${escapedFollowing} --trace keep-escaped-marker`,
      `provider --master-key "seed${lineEnding}tail"/-- --client-key=${quotedFollowing} --mode keep-quoted-marker`,
      `provider --client-key seed\\${lineEnding}--master-key --trace keep-bare-option-value`,
      `provider -kseed\\${lineEnding}-- --trace keep-exact-marker-value`,
    ].join(`${lineEnding}${lineEnding}`);
    const redacted = redactText(input);

    expect(redacted).not.toContain(escapedFollowing);
    expect(redacted).not.toContain(quotedFollowing);
    expect(redacted).not.toContain("tail/--");
    expect(redacted).not.toContain("--master-key --trace");
    expect(redacted).toContain("--trace keep-escaped-marker");
    expect(redacted).toContain("--mode keep-quoted-marker");
    expect(redacted).toContain("--trace keep-bare-option-value");
    expect(redacted).toContain("--trace keep-exact-marker-value");
  }
});

test("repeated escaped and quoted continuations redact one logical token", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const escapedSecret = `repeated-escaped-${lineEnding.length}-suffix-secret`;
    const quotedSecret = `repeated-quoted-${lineEnding.length}-suffix-secret`;
    const input = [
      `provider --api-key seed\\${lineEnding}middle\\${lineEnding}tail((/|<--label=${escapedSecret}>)) --trace keep-repeated-escaped`,
      `provider --client-key "seed\\${lineEnding}middle\\"quoted\\"\\${lineEnding}tail"/－－label:${quotedSecret} --mode keep-repeated-quoted`,
    ].join(`${lineEnding}${lineEnding}`);
    const redacted = redactText(input);

    expect(redacted).not.toContain(escapedSecret);
    expect(redacted).not.toContain(quotedSecret);
    expect(redacted).toContain("--trace keep-repeated-escaped");
    expect(redacted).toContain("--mode keep-repeated-quoted");
  }
});

test("attached logical values redact every fragment and retain later options", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const secrets = [
      "attached-quoted-secret",
      "attached-escaped-secret",
      "attached-short-secret",
    ];
    const input = [
      `provider --api-key="first${lineEnding}${secrets[0]}" --verbose keep-attached-quoted`,
      `provider --client-key:first\\${lineEnding}${secrets[1]} --mode keep-attached-escaped`,
      `provider -k"first${lineEnding}${secrets[2]}" --trace keep-attached-short`,
      "provider x|--master-key=punctuation-secret|--color keep-punctuation-suffix",
    ].join(`${lineEnding}${lineEnding}`);

    const redacted = redactText(input);

    for (const secret of [...secrets, "punctuation-secret"]) {
      expect(redacted).not.toContain(secret);
    }
    for (const retained of [
      "--verbose keep-attached-quoted",
      "--mode keep-attached-escaped",
      "--trace keep-attached-short",
      "|--color keep-punctuation-suffix",
    ]) {
      expect(redacted).toContain(retained);
    }
  }
});

test("pending complete tokens redact embedded punctuation before later safe tokens", () => {
  const boundaries = [
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
  ];
  const lines: string[] = [];
  for (const [index, boundary] of boundaries.entries()) {
    lines.push(
      `provider --api-key plain-${index}-secret${boundary}--trace keep-plain-${index}`,
      `provider --client-key "quoted-${index}-secret"${boundary}--mode keep-quoted-${index}`,
      `provider --master-key (wrapped-${index}-secret)${boundary}--color keep-wrapped-${index}`,
    );
  }

  const redacted = redactText(lines.join("\n"));

  for (const [index, boundary] of boundaries.entries()) {
    expect(redacted).not.toContain(`plain-${index}-secret`);
    expect(redacted).not.toContain(`quoted-${index}-secret`);
    expect(redacted).not.toContain(`wrapped-${index}-secret`);
    expect(redacted).toContain(`keep-plain-${index}`);
    expect(redacted).toContain(`keep-quoted-${index}`);
    expect(redacted).toContain(`keep-wrapped-${index}`);
  }
});

test("numeric-ending pending tokens do not promote punctuation fragments to options", () => {
  const boundaries = ["/", "<", ">"];
  const lines: string[] = [];
  for (const [index, boundary] of boundaries.entries()) {
    lines.push(
      `provider --api-key first-${index}9${boundary}--client-key keep-plain-following-${index} --trace keep-plain-numeric-${index}`,
      `provider --api-key "first-${index}9"${boundary}--client-key keep-quoted-following-${index} --trace keep-quoted-numeric-${index}`,
      `provider --api-key first-${index}\\9${boundary}--client-key keep-escaped-following-${index} --trace keep-escaped-numeric-${index}`,
    );
  }
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    for (const [index, boundary] of boundaries.entries()) {
      lines.push(
        `provider --api-key first-${index}9\\${lineEnding}tail${boundary}--client-key keep-continued-following-${index} --trace keep-continued-numeric-${index}`,
      );
    }
  }

  const redacted = redactText(lines.join("\n"));

  for (let index = 0; index < boundaries.length; index++) {
    for (const kind of ["plain", "quoted", "escaped"]) {
      expect(redacted).toContain(`keep-${kind}-following-${index}`);
      expect(redacted).toContain(`--trace keep-${kind}-numeric-${index}`);
    }
    expect(redacted).toContain(`keep-continued-following-${index}`);
    expect(redacted).toContain(`--trace keep-continued-numeric-${index}`);
  }
});

test("active logical values stop at explicit independent record boundaries", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const input = [
      `provider --api-key "redacted-before-blank${lineEnding}${lineEnding}keep-after-blank-boundary"`,
      `provider --client-key first\\${lineEnding}status=keep-after-status-boundary${lineEnding}keep-after-status-line`,
      `provider --master-key "redacted-before-empty-status${lineEnding}status=${lineEnding}keep-after-empty-status"`,
    ].join(`${lineEnding}${lineEnding}`);

    const redacted = redactText(input);

    expect(redacted).not.toContain("redacted-before-blank");
    expect(redacted).not.toContain("first");
    expect(redacted).not.toContain("redacted-before-empty-status");
    expect(redacted).toContain("keep-after-blank-boundary");
    expect(redacted).toContain("status=keep-after-status-boundary");
    expect(redacted).toContain("keep-after-status-line");
    expect(redacted).toContain(`status=${lineEnding}keep-after-empty-status`);
  }
});

test("URL and email punctuation never turns embedded text into credential options", () => {
  const nearMisses = [
    "https://example.invalid/?arg=--api-key keep-url-query",
    "https://example.invalid/path;--api-key keep-url-param",
    "mailto:person@example.invalid?subject=--api-key keep-mailto-query",
    "mailto:?subject=--api-key keep-mailto-empty-query",
    "person@example.invalid?subject=--api-key keep-email-query",
    "url=https://example.invalid/--api-key keep-assigned-url",
    "href:https://example.invalid/--api-key keep-colon-url",
    "(https://example.invalid/--api-key) keep-parenthesized-url",
    "[https://example.invalid/--api-key] keep-bracketed-url",
    "{https://example.invalid/--api-key} keep-braced-url",
    "prefix|https://example.invalid/--api-key keep-piped-url",
    "prefix,https://example.invalid/--api-key keep-comma-url",
    "url=mailto:?subject=--api-key keep-assigned-mailto",
    "(mailto:?subject=--api-key) keep-parenthesized-mailto",
    "url=www.example.invalid/--api-key keep-assigned-www",
    "https://example.invalid/path(foo)/--api-key keep-url-paren-path",
    "https://example.invalid/path[foo]/--api-key keep-url-bracket-path",
    "https://example.invalid/path{foo}/--api-key keep-url-brace-path",
    "https://example.invalid/path<foo>/--api-key keep-url-angle-path",
    "https://example.invalid/?redirect=(foo)/--api-key keep-url-paren-query",
    "https://example.invalid/wiki/Foo_(bar)/--api-key keep-wiki-path",
    "url=https://example.invalid/path(foo)/--api-key keep-assigned-paren-path",
    "mailto:?subject=(test)/--api-key keep-mailto-paren-query",
  ];

  expect(redactText(nearMisses.join("\n"))).toBe(nearMisses.join("\n"));
});

test("structured values end at syntactic closures before real credential options", () => {
  const cases = [
    {
      input:
        "(https://example.invalid)/--api-key true-secret-paren --trace keep-paren",
      secret: "true-secret-paren",
      retained: "--trace keep-paren",
    },
    {
      input:
        "[https://example.invalid]|--api-key true-secret-bracket --trace keep-bracket",
      secret: "true-secret-bracket",
      retained: "--trace keep-bracket",
    },
    {
      input:
        "{mailto:?subject=test},--api-key true-secret-brace --trace keep-brace",
      secret: "true-secret-brace",
      retained: "--trace keep-brace",
    },
    {
      input:
        "<https://example.invalid>;--api-key true-secret-angle --trace keep-angle",
      secret: "true-secret-angle",
      retained: "--trace keep-angle",
    },
    {
      input:
        "(www.example.invalid):--api-key true-secret-www --trace keep-www",
      secret: "true-secret-www",
      retained: "--trace keep-www",
    },
    {
      input:
        '"https://example.invalid"|--api-key true-secret-quoted --trace keep-quoted',
      secret: "true-secret-quoted",
      retained: "--trace keep-quoted",
    },
    {
      input:
        "(person@example.invalid)/--api-key true-secret-email --trace keep-email",
      secret: "true-secret-email",
      retained: "--trace keep-email",
    },
    {
      input:
        "url=(https://example.invalid)/--api-key true-secret-assigned --trace keep-assigned",
      secret: "true-secret-assigned",
      retained: "--trace keep-assigned",
    },
  ];

  const redacted = redactText(cases.map(({ input }) => input).join("\n"));

  for (const { secret, retained } of cases) {
    expect(redacted).not.toContain(secret);
    expect(redacted).toContain(retained);
  }
});

test("recursive public redaction uses prototype-safe objects", () => {
  const input = JSON.parse(
    '{"safe":"kept","__proto__":{"secret-key":"prototype-secret"},"nested":{"constructor":{"credentials":"nested-secret"}}}',
  ) as Record<string, unknown>;

  const redacted = redactPublicValue(input) as Record<string, unknown>;

  expect(Object.getPrototypeOf(redacted)).toBeNull();
  expect(Object.getPrototypeOf(redacted["nested"])).toBeNull();
  expect(JSON.stringify(redacted)).not.toContain("prototype-secret");
  expect(JSON.stringify(redacted)).not.toContain("nested-secret");
  expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
});

test("recursive public redaction never evaluates accessors or proxy traps", () => {
  let getterCount = 0;
  let proxyTrapCount = 0;
  const nested = Object.create(null) as Record<string, unknown>;
  Object.defineProperties(nested, {
    safe: {
      value: "keep-data-value",
      enumerable: true,
    },
    "secret-key": {
      value: "descriptor-secret",
      enumerable: true,
    },
    marker: {
      get() {
        getterCount++;
        return "getter-secret-marker";
      },
      enumerable: true,
    },
    __proto__: {
      value: { credentials: "prototype-data-secret" },
      enumerable: true,
    },
    constructor: {
      value: { credentials: "constructor-data-secret" },
      enumerable: true,
    },
  });
  const array: unknown[] = [];
  Object.defineProperties(array, {
    0: {
      get() {
        getterCount++;
        return "array-getter-secret";
      },
      enumerable: true,
    },
    1: {
      value: nested,
      enumerable: true,
    },
  });
  const proxy = new Proxy(
    { safe: "proxy-data" },
    {
      ownKeys(target) {
        proxyTrapCount++;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        proxyTrapCount++;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      getPrototypeOf(target) {
        proxyTrapCount++;
        return Reflect.getPrototypeOf(target);
      },
    },
  );
  const input = {
    ordinary: nested,
    array,
    proxy,
  };

  const redacted = redactPublicValue(input) as Record<string, unknown>;
  const serialized = JSON.stringify(redacted);

  expect(getterCount).toBe(0);
  expect(proxyTrapCount).toBe(0);
  expect(serialized).not.toContain("getter-secret-marker");
  expect(serialized).not.toContain("array-getter-secret");
  expect(serialized).not.toContain("descriptor-secret");
  expect(serialized).not.toContain("prototype-data-secret");
  expect(serialized).not.toContain("constructor-data-secret");
  expect(serialized).not.toContain("proxy-data");
  expect(serialized).toContain("keep-data-value");
  expect(Object.getPrototypeOf(redacted)).toBeNull();
  expect(Object.getPrototypeOf(redacted["ordinary"])).toBeNull();
  expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
  expect(JSON.parse(serialized).ordinary.safe).toBe("keep-data-value");
});

test("dot, space, escaped, and single-quoted credential keys fail closed", () => {
  const samples = [
    "oauth.key=dot-key-secret",
    "oauth key = space-key-secret",
    "passphrase: passphrase-secret",
    '{"oauth.key":"json-dot-secret","status":401}',
    String.raw`{"oauth\u002ekey":"escaped-dot-secret","status":401}`,
    String.raw`{"oauth\u002ekey":"malformed-escaped-secret","status" 401}`,
    "{'session key':'single-quoted-secret','status':401}",
    "{'bearerKey':'single-camel-secret';'status':401}",
    String.raw`{'oauth\u002ekey':'single-escaped-secret','status' 401}`,
  ];

  const redacted = redactText(samples.join("\n"));
  for (const secret of [
    "dot-key-secret",
    "space-key-secret",
    "passphrase-secret",
    "json-dot-secret",
    "escaped-dot-secret",
    "malformed-escaped-secret",
    "single-quoted-secret",
    "single-camel-secret",
    "single-escaped-secret",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("[REDACTED]");
});

test("credential records nested inside non-sensitive wrapper values are still redacted", () => {
  const input = [
    "message=Authorization: Bearer wrapped-auth-secret",
    "detail=oauth_token=wrapped-oauth-secret",
    '{"message":"Authorization: Bearer wrapped-json-auth-secret"}',
    '{"detail":"consumerSecret=wrapped-json-consumer-secret"}',
    "status=401 keep-wrapper-status",
  ].join("\n");

  const redacted = redactText(input);
  for (const secret of [
    "wrapped-auth-secret",
    "wrapped-oauth-secret",
    "wrapped-json-auth-secret",
    "wrapped-json-consumer-secret",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("status=401 keep-wrapper-status");
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

test("authorization folding preserves diagnostics after a syntactically complete value", () => {
  const input = [
    "Authorization: AWS4-HMAC-SHA256 Credential=diagnostic-access/20260727/us-east-1/bedrock/aws4_request,",
    " SignedHeaders=content-type;host;x-amz-date,",
    " Signature=diagnostic-signature",
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

test("empty sensitive headers fail closed on indented diagnostic-looking continuations", () => {
  const input = [
    "Authorization:",
    " stack=Error:opaque-authorization-credential",
    "Proxy-Authorization:",
    " detail=opaque-proxy-credential",
    "Cookie:",
    " status=opaque-cookie-credential",
    "Set-Cookie:",
    " message=opaque-set-cookie-credential",
    "X-Request-ID: keep-adjacent-header",
  ].join("\n");

  const redacted = redactText(input);
  for (const secret of [
    "opaque-authorization-credential",
    "opaque-proxy-credential",
    "opaque-cookie-credential",
    "opaque-set-cookie-credential",
  ]) {
    expect(redacted).not.toContain(secret);
  }
  expect(redacted).toContain("X-Request-ID: keep-adjacent-header");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(4);
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

test("ambiguous folded credential boundaries fail closed across headers and line endings", () => {
  const headers = [
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
  ];

  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    for (const header of headers) {
      const label = header.toLowerCase().replaceAll("-", "_");
      for (const headerSyntax of [header, JSON.stringify(header)]) {
        const cases = [
          `${headerSyntax}:${lineEnding} message=${label}_empty_secret${lineEnding}status=418 keep-empty-boundary`,
          `${headerSyntax}: seed=${label}_dangling_seed,${lineEnding} stack=Error:${label}_dangling_secret${lineEnding}status=418 keep-dangling-boundary`,
          `${headerSyntax}: seed=${label}_separator_seed,${lineEnding} ,${lineEnding} detail=${label}_separator_secret${lineEnding}status=418 keep-separator-boundary`,
          `${headerSyntax}: seed=${label}_serialized_seed, nonce:${label}_serialized_secret${lineEnding}status=418 keep-serialized-boundary`,
          `${headerSyntax}: seed=${label}_quoted_serialized_seed, "nonce":${label}_quoted_serialized_secret${lineEnding}status=418 keep-quoted-serialized-boundary`,
        ];

        for (const input of cases) {
          const redacted = redactText(input);
          expect(redacted).not.toContain(`${label}_empty_secret`);
          expect(redacted).not.toContain(`${label}_dangling_secret`);
          expect(redacted).not.toContain(`${label}_separator_secret`);
          expect(redacted).not.toContain(`${label}_serialized_secret`);
          expect(redacted).not.toContain(`${label}_quoted_serialized_secret`);
          expect(redacted).toContain("status=418 keep-");
        }
      }
    }
  }
});

test("properly quoted serialized values retain adjacent non-sensitive fields", () => {
  for (const header of [
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
  ]) {
    const label = header.toLowerCase().replaceAll("-", "_");
    const input = `{"${header}":"${label}_serialized_secret","status":418,"message":"keep-${label}"}`;
    const redacted = redactText(input);

    expect(redacted).not.toContain(`${label}_serialized_secret`);
    expect(redacted).toContain('"status":418');
    expect(redacted).toContain(`"message":"keep-${label}"`);
  }
});

test("whitespace-only folds keep sensitive header records fail closed", () => {
  const headers = [
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
  ];

  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    for (const header of headers) {
      const label = header.toLowerCase().replaceAll("-", "_");
      const cases = [
        [
          `${header}: seed=${label}_complete_seed`,
          " \t",
          ` ${label}_complete_fragment`,
          "status=418 keep-complete-boundary",
        ],
        [
          `${header}:`,
          "\t ",
          ` ${label}_empty_fragment`,
          "status=418 keep-empty-boundary",
        ],
        [
          `${header}: seed=${label}_dangling_seed,`,
          "  ",
          ` stack=Error:${label}_dangling_fragment`,
          "status=418 keep-dangling-boundary",
        ],
        [
          `${header}: seed=${label}_separator_seed,`,
          " ,\t",
          ` detail=${label}_separator_fragment`,
          "status=418 keep-separator-boundary",
        ],
      ];

      for (const lines of cases) {
        const redacted = redactText(lines.join(lineEnding));
        for (const secret of [
          `${label}_complete_fragment`,
          `${label}_empty_fragment`,
          `${label}_dangling_fragment`,
          `${label}_separator_fragment`,
        ]) {
          expect(redacted).not.toContain(secret);
        }
        expect(redacted).toContain("status=418 keep-");
      }
    }
  }
});

test("raw quoted sensitive headers redact escaped and unescaped same-line tails", () => {
  for (const header of [
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
  ]) {
    const label = header.toLowerCase().replaceAll("-", "_");
    for (const quote of ['"', "'"]) {
      for (const separator of [",", ";"]) {
        for (const escaped of [false, true]) {
          const credential = escaped
            ? quote === '"'
              ? `${label}_quoted_\\"fragment`
              : `${label}_quoted_\\'fragment`
            : `${label}_quoted_fragment`;
          const input = [
            `${header}: ${quote}${credential}${quote}${separator} extension=${label}_tail_fragment`,
            "status=418 keep-raw-quoted-boundary",
          ].join("\n");
          const redacted = redactText(input);

          expect(redacted).not.toContain(`${label}_quoted_`);
          expect(redacted).not.toContain(`${label}_tail_fragment`);
          expect(redacted).toContain("status=418 keep-raw-quoted-boundary");
        }
      }
    }
  }
});

test("generic credential fields redact folded and escaped raw records", () => {
  for (const field of [
    "x-api-key",
    "x-goog-api-key",
    "client-secret",
    "auth-token",
  ]) {
    const label = field.replaceAll("-", "_");
    for (const lineEnding of ["\n", "\r\n", "\r"]) {
      const cases = [
        [
          `${field}: ${label}_first_fragment`,
          ` ${label}_folded_fragment`,
          "status=418 keep-generic-fold-boundary",
        ],
        [
          `${field}:`,
          "\t",
          ` ${label}_empty_fragment`,
          "status=418 keep-generic-empty-boundary",
        ],
        [
          `${field}: "${label}_quoted_\\"fragment", suffix=${label}_quoted_tail`,
          "status=418 keep-generic-quoted-boundary",
        ],
      ];

      for (const lines of cases) {
        const redacted = redactText(lines.join(lineEnding));
        for (const secret of [
          `${label}_first_fragment`,
          `${label}_folded_fragment`,
          `${label}_empty_fragment`,
          `${label}_quoted_`,
          `${label}_quoted_tail`,
        ]) {
          expect(redacted).not.toContain(secret);
        }
        expect(redacted).toContain("status=418 keep-generic-");
      }
    }
  }
});

test("properly serialized generic credential fields retain independent siblings", () => {
  for (const field of [
    "x-api-key",
    "x-goog-api-key",
    "client-secret",
    "auth-token",
  ]) {
    const label = field.replaceAll("-", "_");
    const input = `{"${field}":"${label}_serialized_fragment","status":418,"message":"keep-${label}"}`;
    const redacted = redactText(input);

    expect(redacted).not.toContain(`${label}_serialized_fragment`);
    expect(redacted).toContain('"status":418');
    expect(redacted).toContain(`"message":"keep-${label}"`);
  }
});

test("folded redaction scaling stays linear across newline styles and multi-megabyte inputs", () => {
  const lineCounts = [3_000, 12_000, 50_000];

  for (const lineEnding of ["\n", "\r"]) {
    const inputs = lineCounts.map((lineCount) => {
      const folded = Array.from(
        { length: lineCount },
        (_, index) => ` extension-${index}=credential-fragment-${index},`,
      );
      return [
        "Authorization: Custom seed=credential-seed,",
        ...folded,
        " final-extension=credential-tail",
        "status=429 keep-after-scaling-record",
      ].join(lineEnding);
    });

    expect(inputs[2]!.length).toBeGreaterThan(2 * 1024 * 1024);
    redactText(inputs[0]!);
    const elapsed: number[] = [];
    for (const [sizeIndex, input] of inputs.entries()) {
      const samples: number[] = [];
      let redacted = "";
      for (let run = 0; run < 3; run++) {
        const startedAt = performance.now();
        redacted = redactText(input);
        samples.push(performance.now() - startedAt);
      }
      elapsed.push(Math.min(...samples));

      expect(redacted).not.toContain("credential-seed");
      expect(redacted).not.toContain(
        `credential-fragment-${lineCounts[sizeIndex]! - 1}`,
      );
      expect(redacted).not.toContain("credential-tail");
      expect(redacted).toContain("status=429 keep-after-scaling-record");
    }

    expect(elapsed[0]!).toBeLessThan(200);
    expect(elapsed[1]!).toBeLessThan(400);
    expect(elapsed[2]!).toBeLessThan(800);
  }
});

test("command-text option redaction stays bounded on multi-megabyte captured output", () => {
  const lines = Array.from(
    { length: 30_000 },
    (_, index) =>
      `provider --api-key "command-scaling-secret-${index}" --verbose keep-command-${index}`,
  );
  const input = lines.join("\n");
  expect(input.length).toBeGreaterThan(2 * 1024 * 1024);

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("command-scaling-secret-0");
  expect(redacted).not.toContain("command-scaling-secret-29999");
  expect(redacted).toContain("--verbose keep-command-0");
  expect(redacted).toContain("--verbose keep-command-29999");
  expect(elapsedMs).toBeLessThan(1_500);
});

test("dense active continuation suffixes remain linear and fully redacted", () => {
  const continuation =
    `tail${"/--label=opaque".repeat(36_000)}` +
    "/--label=terminal-active-continuation-secret";
  const input =
    `provider --api-key seed\\\n${continuation} ` +
    "--trace keep-dense-active-continuation";
  expect(input.length).toBeGreaterThan(512 * 1024);

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("terminal-active-continuation-secret");
  expect(redacted).toContain("--trace keep-dense-active-continuation");
  expect(elapsedMs).toBeLessThan(1_500);
});

test("command-text punctuation discovery remains linear on a dense single token", () => {
  const input =
    Array.from(
      { length: 50_000 },
      (_, index) => `diagnostic/--verbose)keep-${index};`,
    ).join("") +
    "diagnostic/--api-key punctuation-density-secret";
  expect(input.length).toBeGreaterThan(1024 * 1024);

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("punctuation-density-secret");
  expect(redacted).toContain("keep-0");
  expect(redacted).toContain("keep-49999");
  expect(elapsedMs).toBeLessThan(1_500);
});

test("dense punctuation-delimited sensitive options remain linear", () => {
  const input = Array.from(
    { length: 6_400 },
    (_, index) => `x|--api-key=dense-sensitive-${index}`,
  ).join("");

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("dense-sensitive-0");
  expect(redacted).not.toContain("dense-sensitive-6399");
  expect(redacted.match(/\[REDACTED\]/g)?.length).toBe(6_400);
  expect(elapsedMs).toBeLessThan(1_500);
});

test("command-text scanning remains linear across many physical-line tokens", () => {
  const input =
    Array.from(
      { length: 8_000 },
      (_, index) => `--verbose keep-token-${index}`,
    ).join(" ") +
    " --api-key many-token-secret";

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("many-token-secret");
  expect(redacted).toContain("--verbose keep-token-0");
  expect(redacted).toContain("--verbose keep-token-7999");
  expect(elapsedMs).toBeLessThan(2_000);
});

test("quoted command-segment scanning remains linear with many quoted fields", () => {
  const input =
    Array.from(
      { length: 8_000 },
      (_, index) => `"keep-quoted-${index}"`,
    ).join(" ") +
    ' "provider --api-key quoted-scaling-secret --verbose keep-quoted-option"';

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("quoted-scaling-secret");
  expect(redacted).toContain("keep-quoted-0");
  expect(redacted).toContain("keep-quoted-7999");
  expect(redacted).toContain("--verbose keep-quoted-option");
  expect(elapsedMs).toBeLessThan(2_000);
});

test("unterminated command quotes recover later standalone credential syntax", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const input = [
      'provider "unterminated diagnostic --api-key unmatched-double-secret --trace keep-unmatched-double',
      "provider 'unterminated diagnostic --client-key=unmatched-single-secret --mode keep-unmatched-single",
      'provider "unterminated diagnostic －－ --master-key unmatched-fullwidth-secret --color keep-unmatched-fullwidth',
      'provider "unterminated diagnostic \\-- --service-auth=unmatched-escaped-marker-secret --verbose keep-unmatched-escaped-marker',
      'provider "unterminated diagnostic \'--\' --credentials unmatched-quoted-marker-secret --debug keep-unmatched-quoted-marker',
    ].join(lineEnding);

    const redacted = redactText(input);

    for (const secret of [
      "unmatched-double-secret",
      "unmatched-single-secret",
      "unmatched-fullwidth-secret",
      "unmatched-escaped-marker-secret",
      "unmatched-quoted-marker-secret",
    ]) {
      expect(redacted).not.toContain(secret);
    }
    for (const retained of [
      "keep-unmatched-double",
      "keep-unmatched-single",
      "keep-unmatched-fullwidth",
      "keep-unmatched-escaped-marker",
      "keep-unmatched-quoted-marker",
    ]) {
      expect(redacted).toContain(retained);
    }
  }
});

test("nested unterminated quotes cannot hide later credential syntax", () => {
  for (const lineEnding of ["\n", "\r\n", "\r"]) {
    const cases = [
      {
        input:
          `provider "outer 'inner --api-key nested-double-single-secret ` +
          "--trace keep-nested-double-single",
        secret: "nested-double-single-secret",
        retained: "keep-nested-double-single",
      },
      {
        input:
          `provider 'outer "inner --client-key=nested-single-double-secret` +
          "|--mode keep-nested-single-double",
        secret: "nested-single-double-secret",
        retained: "keep-nested-single-double",
      },
      {
        input:
          String.raw`provider "outer \'inner --credentials nested-escaped-opposite-secret ` +
          "--debug keep-nested-escaped-opposite",
        secret: "nested-escaped-opposite-secret",
        retained: "keep-nested-escaped-opposite",
      },
      {
        input:
          `provider "outer 'inner tail\\${lineEnding}` +
          "diagnostic/--service-auth nested-continued-secret " +
          "--color keep-nested-continued",
        secret: "nested-continued-secret",
        retained: "keep-nested-continued",
      },
    ];

    for (const sample of cases) {
      const redacted = redactText(sample.input);
      expect(redacted, sample.input).not.toContain(sample.secret);
      expect(redacted, sample.input).toContain(sample.retained);
    }
  }
});

test("unterminated quote recovery preserves valid quoted, escaped, and exact-sentinel data", () => {
  const inputs = [
    'provider "unterminated diagnostic \'--api-key\' quoted-benign --trace keep-valid-quoted',
    String.raw`provider "unterminated diagnostic \--api-key escaped-benign --trace keep-escaped-content`,
    'provider "unterminated diagnostic -- --api-key exact-sentinel-positional --trace exact-sentinel-positional-trace',
  ];

  for (const input of inputs) {
    expect(redactText(input)).toBe(input);
  }
});

test("unterminated quote recovery stays linear on dense captured output", () => {
  const lines = Array.from(
    { length: 22_000 },
    (_, index) =>
      `provider "unterminated-${index} --api-key dense-unmatched-secret-${index} --trace keep-dense-unmatched-${index}`,
  );
  const input = lines.join("\n");
  expect(input.length).toBeGreaterThan(2 * 1024 * 1024);

  const startedAt = performance.now();
  const redacted = redactText(input);
  const elapsedMs = performance.now() - startedAt;

  expect(redacted).not.toContain("dense-unmatched-secret-0");
  expect(redacted).not.toContain("dense-unmatched-secret-21999");
  expect(redacted).toContain("keep-dense-unmatched-0");
  expect(redacted).toContain("keep-dense-unmatched-21999");
  expect(elapsedMs).toBeLessThan(2_000);
});
