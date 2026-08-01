import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  APIError,
  API_VERSION,
  LatchClient,
  LatchUnavailable,
  MEDIA_TYPE,
  NotAllowedError,
  ProtocolError,
} from "../dist/index.js";

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

async function requestBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function decision(requestId, value = "ALLOW") {
  return {
    api_version: API_VERSION,
    request_id: requestId,
    decision: value,
    risk: { score: 0, level: "LOW" },
    identity: { verified: true },
    policy: { decision_source: "test", hard_deny: false },
  };
}

function json(response, value, status = 200) {
  const body = JSON.stringify(value);
  response.writeHead(status, { "content-type": MEDIA_TYPE, "content-length": Buffer.byteLength(body) });
  response.end(body);
}

test("decide sends the authenticated v1 contract", async () => {
  await withServer(async (request, response) => {
    assert.equal(request.url, "/v1/decisions");
    assert.equal(request.headers.authorization, "Bearer secret");
    assert.equal(request.headers["content-type"], MEDIA_TYPE);
    const body = await requestBody(request);
    json(response, decision(body.request_id));
  }, async (url) => {
    const result = await new LatchClient(url, { token: "secret" }).decide({ tool: "filesystem.read" });
    assert.equal(result.allowed, true);
  });
});

test("guard executes only an explicit ALLOW", async () => {
  for (const outcome of ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]) {
    await withServer(async (request, response) => {
      const body = await requestBody(request);
      json(response, decision(body.request_id, outcome));
    }, async (url) => {
      let executed = false;
      const client = new LatchClient(url);
      if (outcome === "ALLOW") {
        const value = await client.guard({ tool: "safe.tool" }, () => { executed = true; return "done"; });
        assert.equal(value, "done");
      } else {
        await assert.rejects(
          client.guard({ tool: "unsafe.tool" }, () => { executed = true; }),
          NotAllowedError,
        );
      }
      assert.equal(executed, outcome === "ALLOW");
    });
  }
});

test("HTTP errors and unavailable servers fail closed", async () => {
  await withServer((_request, response) => {
    json(response, { api_version: API_VERSION, error: { code: "unauthorized", message: "denied" } }, 401);
  }, async (url) => {
    await assert.rejects(new LatchClient(url).decide({ tool: "safe.tool" }), APIError);
  });
  await assert.rejects(
    new LatchClient("http://127.0.0.1:1", { timeoutMs: 100 }).decide({ tool: "safe.tool" }),
    LatchUnavailable,
  );
});

test("timeout covers the complete response body", async () => {
  await withServer(async (request, response) => {
    const body = await requestBody(request);
    const payload = JSON.stringify(decision(body.request_id));
    response.writeHead(200, { "content-type": MEDIA_TYPE, "content-length": Buffer.byteLength(payload) });
    response.flushHeaders();
    setTimeout(() => response.end(payload), 250);
  }, async (url) => {
    const started = Date.now();
    await assert.rejects(
      new LatchClient(url, { timeoutMs: 50 }).decide({ tool: "safe.tool" }),
      LatchUnavailable,
    );
    assert.ok(Date.now() - started < 200, "client waited beyond its configured timeout");
  });
});

test("malformed, mismatched, redirected, and oversized responses fail closed", async () => {
  const cases = [
    (_request, response) => json(response, "not a decision"),
    (_request, response) => json(response, decision("req_wrong000")),
    (_request, response) => json(response, { padding: "x".repeat(2048) }),
    (_request, response) => { response.writeHead(307, { location: "https://example.invalid" }); response.end(); },
  ];
  for (const handler of cases) {
    await withServer(handler, async (url) => {
      await assert.rejects(
        new LatchClient(url, { maxResponseBytes: 1024 }).decide({ tool: "safe.tool" }),
        (error) => error instanceof ProtocolError || error instanceof LatchUnavailable,
      );
    });
  }
});

test("client interoperates with a live Latch API", { skip: !process.env.LATCH_TEST_URL }, async () => {
  const result = await new LatchClient(process.env.LATCH_TEST_URL, {
    token: process.env.LATCH_API_TOKEN,
  }).decide({ tool: "filesystem.read", arguments: { path: "./README.md" } });
  assert.equal(result.allowed, true);
  assert.equal(result.identity.verified, true);
});
