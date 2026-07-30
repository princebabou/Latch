import assert from "node:assert/strict";
import test from "node:test";

async function render(pathname = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${pathname}`, {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the Latch landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Latch — Security enforcement for AI agents<\/title>/i);
  assert.match(html, /Let agents move\./);
  assert.match(html, /Keep control\./);
  assert.match(html, /Decision playground/i);
  assert.match(html, /REQUIRE APPROVAL/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("server-renders documentation and playground routes", async () => {
  const docsResponse = await render("/docs/quickstart");
  const docsHtml = await docsResponse.text();
  assert.equal(docsResponse.status, 200);
  assert.match(docsHtml, /Quickstart/);
  assert.match(docsHtml, /latch init --profile balanced/);

  const playgroundResponse = await render("/playground");
  const playgroundHtml = await playgroundResponse.text();
  assert.equal(playgroundResponse.status, 200);
  assert.match(playgroundHtml, /Decision playground/);
  assert.match(playgroundHtml, /Workspace read/);
});
