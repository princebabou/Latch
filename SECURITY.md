# Security policy

Latch sits on a security boundary. Please do not open a public issue for a
suspected vulnerability.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature on the repository
Security tab. Include:

- the affected version or commit;
- the policy and action shape needed to reproduce the issue;
- the expected and observed verdict;
- whether the issue can permit a blocked action to reach an upstream tool;
- a minimal reproducer, if one can be shared safely.

Do not include live credentials, private keys, customer data, or production
endpoints. Replace them with synthetic values.

We will acknowledge the report through the private advisory, investigate the
security boundary affected, and coordinate a fix and disclosure there.

## Supported versions

Security fixes are made against the latest released minor version and the
default branch. Users should upgrade to the latest release because policies,
parsers, and protocol defenses evolve together.

## Deployment expectations

Run Latch with the least operating-system privileges available. Treat policy
files, launcher configuration, the trusted `--agent` binding, approval state,
budget state, and the Latch executable as security-sensitive. An actor who can
replace any of them can change the enforcement boundary.
