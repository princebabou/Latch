# CI/CD and GitHub Actions

Latch can enforce an intended deployment, infrastructure, release, or other
automation action before the real command starts. The packaged GitHub Action
installs an exact checksummed Latch release, evaluates the action, writes a
native annotation and job summary, exposes structured outputs, and exits
successfully only for an explicit `ALLOW`.

## One-step GitHub Action

Commit a policy such as `latch.yaml`, then place the gate immediately before
the real side effect:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v7

  - name: Enforce deployment policy
    id: latch
    uses: princebabou/Latch@v0.2.0
    with:
      config: latch.yaml
      agent: github-actions
      tool: deployment.apply
      operation: write
      resource: production
      arguments: '{"environment":"production","service":"api"}'

  - name: Deploy
    if: steps.latch.outputs.allowed == 'true'
    run: ./scripts/deploy.sh production
```

Pin the action to a full release tag or commit SHA. A full commit SHA gives the
strongest third-party action integrity. Do not use `continue-on-error` on the
Latch step and do not place the deployment in a parallel job that can run
without the gate.

The action supports GitHub-hosted Linux, macOS, and Windows runners. It
downloads the requested release archive and verifies it against the release
SHA-256 checksum before executing it. Set `latch-binary` only when the workflow
has already produced or installed a trusted binary.

## Inputs

| Input | Required | Meaning |
|---|---:|---|
| `config` | no | Policy path; defaults to `latch.yaml` |
| `agent` | yes | Operator-controlled identity bound by the workflow |
| `tool` | yes | Intended tool or capability |
| `operation` | no | Normalized operation such as `write` or `execute` |
| `resource` | no | Intended file, URL, environment, or deployment target |
| `arguments` | no | Strict JSON object; duplicate keys and trailing data are rejected |
| `latch-version` | no | Exact release installed by the action; never defaults to `latest` |
| `latch-binary` | no | Trusted local binary path that skips installation |

Treat action inputs as an intended action description, not as shell text. Latch
passes them through environment variables and structured process arguments;
it never evaluates them as a command.

## Outputs and exit behavior

The action exposes `request-id`, `decision`, `allowed`, `approval-required`,
`fail-closed`, `risk-score`, `risk-level`, `decision-source`, `hard-deny`,
`triggered-rules`, and `reasons`. Rule and reason outputs are compact JSON
arrays.

`allowed` is `true` only for an explicit `ALLOW`. Both `BLOCK` and
`REQUIRE_APPROVAL` fail the action with exit code 3. Configuration, state,
audit, installation, or GitHub reporting errors fail with exit code 1. Missing
runner output or summary files are treated as enforcement failures, so a later
step cannot observe an `ALLOW` output after incomplete reporting.

GitHub annotations escape workflow-command control characters, and job-summary
values are rendered as escaped text. Model-controlled tool or resource values
cannot create new annotations or inject raw HTML into the summary.

## Native CLI adapter

Other CI systems can call the same adapter directly:

```sh
latch ci \
  --provider generic \
  --config latch.yaml \
  --agent deployment-bot \
  --tool deployment.apply \
  --action write \
  --resource production \
  --arguments-json '{"environment":"production"}' \
  --json
```

Provider `auto` selects GitHub only when `GITHUB_ACTIONS=true`; otherwise it
uses generic terminal or JSON output. Provider `github` writes the current
step's `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY` files and emits a native
notice, warning, or error annotation.

Unlike `latch check`, `latch ci` is an immediate execution gate. An allowed
decision reserves matching action-budget capacity before returning. Every
decision is audited. CI environment metadata is included for traceability but
never establishes identity; only the operator-controlled `--agent` binding is
verified.

## Reusable workflow

The repository includes `.github/workflows/latch-policy-gate.yml` for teams
that prefer a separate enforcement job:

```yaml
jobs:
  policy:
    uses: princebabou/Latch/.github/workflows/latch-policy-gate.yml@v0.2.0
    with:
      config: latch.yaml
      agent: github-actions
      tool: deployment.apply
      operation: write
      resource: production
      arguments: '{"environment":"production"}'

  deploy:
    needs: policy
    if: needs.policy.outputs.allowed == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: ./scripts/deploy.sh production
```

Keep the policy job free of write permissions and secrets when possible. Grant
deployment credentials only to the downstream job that depends on the explicit
allow result. GitHub environments can add a second, platform-managed approval
layer for production.

## Approval-required decisions

The CI adapter does not open an interactive prompt. A
`REQUIRE_APPROVAL` result stops the workflow and identifies the triggering
rules in the annotation, job summary, outputs, and audit event. Issue a
time-bound grant through an operator-controlled Latch environment, then rerun
the exact action, or combine Latch with GitHub environment approvals. Never
convert `REQUIRE_APPROVAL` into `ALLOW` inside workflow YAML.

## Security checklist

- Pin Latch and every third-party action to an immutable commit SHA in
  high-assurance workflows.
- Keep the policy, workflow, and trusted agent identity under code review and
  branch protection.
- Give the policy-gate job only `contents: read` unless it genuinely needs more.
- Put deployment credentials in the post-gate job or step, not in action
  arguments.
- Do not use `continue-on-error`, shell string interpolation, or an unguarded
  parallel deployment path.
- Persist the audit and budget state required by the policy when using
  self-hosted runners.
- Treat `GITHUB_*` metadata as audit context, not authenticated identity.
