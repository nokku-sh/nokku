# Security

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private reporting instead:

1. Open this repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Tell us as much of this as you can:
   - Which part and version, and how it runs (your platform, self-hosted or hosted)
   - What the issue is and what an attacker gains
   - Steps to reproduce, or a minimal proof of concept
   - Logs that help, with secrets and tokens removed

Reports are handled confidentially. If you would like credit in the advisory or the changelog, say so.

What to expect:

- **Acknowledgement** within 48 hours
- **Triage** and a severity within 5 business days
- **A fix or clear guidance** within 30 days, depending on complexity and impact

Only the latest release gets security fixes. Older releases are not patched, so upgrade to the newest one.

## Each part

Each part has its own file. It says what is in scope, how to run that part safely and how it is built.

| Part             | File                                           |
| ---------------- | ---------------------------------------------- |
| Core and web app | [core/SECURITY.md](./core/SECURITY.md)         |
| Daemon           | [daemon/SECURITY.md](./daemon/SECURITY.md)     |
| CLI              | [cli/SECURITY.md](./cli/SECURITY.md)           |
| Shared packages  | [internal/SECURITY.md](./internal/SECURITY.md) |
