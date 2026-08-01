# Latch developer portal

The public product, documentation, and interactive decision-playground site
for [Latch](https://github.com/princebabou/Latch).

## Local development

```bash
npm ci
npm run dev
```

The site uses vinext and is packaged for Cloudflare Worker-compatible
deployment through OpenAI Sites.

## Validate

```bash
npm run build
npm test
```

Documentation content is grounded in the repository's current CLI, policy,
integration, deployment, and security behavior.
