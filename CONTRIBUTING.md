# Contributing to VEYRON

VEYRON is a community security engineering project. Contributions of
scanner adapters, language support, docs, and brand work are welcome.

## Ground rules

1. **No secrets in contributions.** Never add real credentials, tokens, or
   private keys — even in fixtures or tests.
2. **No paid dependencies.** Every new dependency must be installable at zero
   cost and compatible with the ₹0 constraint.
3. **Tests required.** New scanner adapters ship with deterministic unit
   tests (mocked) plus real-tool integration tests guarded by tool presence.
4. **AI remains optional.** Never gate scanner functionality behind AI.
5. **Scope controls are non-negotiable.** DAST changes require explicit
   authorisation + allowlist + budget enforcement.

## How to contribute

- Fork the repository, create a feature branch, run `pytest -q` locally.
- Submit a pull request with a clear description and any docs updates.
- Maintainers review for security implications before merging.

## Code style

- Python 3.10+; type hints on public functions; docstrings on modules.
- Black-style formatting (4-space indent, double quotes).
- Commit messages: imperative, short subject line, body when needed.

## Reporting issues

Use GitHub issues. For security-sensitive concerns, see SECURITY.md.
