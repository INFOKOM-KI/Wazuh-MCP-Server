# Contributing to Wazuh MCP Server

Thank you for your interest in contributing to **Wazuh MCP Server**, a defensive Model Context Protocol (MCP) server for Wazuh SIEM and blue-team security operations. Contributions that improve correctness, security, reliability, performance, documentation, and usability are welcome.

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Before You Start](#before-you-start)
- [Development Environment](#development-environment)
- [Running Tests and Checks](#running-tests-and-checks)
- [Development Guidelines](#development-guidelines)
- [Security and Privacy Requirements](#security-and-privacy-requirements)
- [Documentation Changes](#documentation-changes)
- [Commit and Pull Request Workflow](#commit-and-pull-request-workflow)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [License](#license)

## Ways to Contribute

You can contribute by:

- Reporting reproducible bugs or unexpected behavior.
- Proposing focused improvements or new defensive SOC capabilities.
- Fixing defects and adding regression tests.
- Improving detection logic, alert analysis, correlation, threat-intelligence integrations, investigation workflows, or error handling.
- Improving setup instructions, configuration guidance, runbooks, and examples.
- Reviewing pull requests and helping clarify issues.

For substantial changes, open an issue first to discuss the problem, expected behavior, and proposed approach. This helps avoid duplicating work and makes the scope clear before implementation.

## Before You Start

1. Check the existing issues and pull requests for related work.
2. Read the project [README](https://github.com/INFOKOM-KI/Wazuh-MCP-Server/blob/main/README.md) and the relevant module documentation.
3. Keep each change focused. A narrowly scoped pull request is easier to review and safer to merge.
4. Do not include production credentials, customer data, real incident artifacts, or other sensitive information in issues, commits, fixtures, screenshots, or logs.

If you are unsure whether a change belongs in the project, describe the problem and intended outcome in an issue before making a large implementation.

## Development Environment

### Prerequisites

- Python **3.11 or newer**.
- Git.
- A virtual environment for Python dependencies.
- `pytest` and the project's dependencies from `requirements.txt` for running the test suite.

A live Wazuh deployment and third-party threat-intelligence credentials are not required for ordinary unit tests. Integration tests that depend on external services should be clearly identified and run only against an authorized test or lab environment.

### Clone the repository

Fork the repository on GitHub, then clone your fork:

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git remote add upstream https://github.com/INFOKOM-KI/Wazuh-MCP-Server.git
```

If you already have a local clone, make sure you are working on a feature branch and that your base branch is up to date with the project's default branch.

### Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Keep development dependencies isolated from system Python. Do not commit the virtual environment, generated caches, logs, local configuration, API keys, or credentials.

### Optional document-conversion components

Some document-conversion capabilities are optional. Follow the relevant instructions in `README.md` and `setup.sh` before enabling them. In particular, do not enable optional OCR/model installation just to work on unrelated code: these components may require substantial disk space, downloads, or additional host-level dependencies.

### Configure services safely

Use environment variables and a local, untracked configuration file for any credentials needed for manual integration testing. Never place real secrets in source code or commit them. Use a dedicated Wazuh lab or another authorized test environment; do not use production systems as a test fixture.

## Running Tests and Checks

Run checks from the repository root, inside the development virtual environment.

### Test suite

```bash
python -m pytest -q
```

For a particular test module or file, pass its path to `pytest`, for example:

```bash
python -m pytest -q tests/<test_file>.py
```

Replace `<test_file>.py` with the relevant existing test filename. If a test requires a live service or API credential, document that requirement and do not make ordinary unit tests depend on an unavailable external service.

### Required guardrail check

Run the repository's guardrail checker in strict mode:

```bash
python3 check_guardrails.py --strict
```

The command must exit successfully before a change is ready to merge. Address any findings introduced by your change. Do not silence or weaken a guardrail simply to make the check pass; if a guardrail needs to change, explain the rationale and include appropriate tests or documentation in the same pull request.

### Before submitting

At minimum:

- Run the relevant tests for the changed behavior.
- Run the full test suite when practical.
- Run `python3 check_guardrails.py --strict`.
- Review the final diff for accidental changes, generated files, secrets, and sensitive data.
- Confirm that logs and error responses do not expose credentials or unnecessary personal or incident data.

Include the commands you ran and their results in the pull request description. If a check could not be run, state why instead of implying it passed.

## Development Guidelines

### Python and maintainability

- Follow the style and patterns already used in the surrounding code.
- Prefer clear names, focused functions, explicit error handling, and type hints where they improve clarity.
- Keep changes small and avoid unrelated refactoring in bug-fix pull requests.
- Avoid adding dependencies unless they provide a clear benefit that cannot reasonably be achieved with existing dependencies. Explain new dependencies and any operational or security impact in the pull request.
- Do not commit generated outputs, local databases, caches, trained models, downloaded corpora, or benchmark artifacts unless they are explicitly required and approved for the feature.

### Project structure

Keep changes in the part of the codebase that owns the behavior. Common areas include:

- `mcp_server/core/`: shared configuration, HTTP handling, security controls, auditing, and other core services.
- `mcp_server/wazuh/`: Wazuh Indexer and Manager integration.
- `mcp_server/correlation/`: alert correlation and related analysis.
- `mcp_server/threat_intel/`: threat-intelligence provider integrations.
- `mcp_server/agents/`: investigation and playbook workflows.
- `mcp_server/tools/`: MCP tool implementations and registration.
- `resource/`: project resources and operational guidance.
- `scripts/` and `tests/`: supporting scripts and automated tests.

Follow the current architecture rather than creating a parallel implementation of an existing shared capability.

### MCP tools, auditing, and output handling

When adding or changing an MCP tool:

- Follow the project's existing tool registration and `@blueteam_tool` conventions where applicable.
- Preserve the established audit, redaction, and response-truncation pipeline. Do not bypass shared controls to simplify an implementation.
- Validate and bound untrusted input. Handle missing fields, malformed responses, upstream timeouts, rate limits, and partial failures explicitly.
- Return structured, actionable errors without exposing stack traces, credentials, internal secrets, or unnecessary raw incident data.
- Keep tool descriptions and parameter schemas accurate; document any behavior or configuration changes.
- Add tests for both expected results and relevant failure cases.

### Wazuh changes and operational behavior

- Preserve compatibility with the project's supported Python and dependency versions.
- Avoid assuming that every Wazuh deployment has identical fields, decoders, rules, indices, permissions, or optional integrations.
- Make external-service behavior resilient: use the project's shared HTTP facilities and established timeout, retry, and circuit-breaker patterns rather than introducing ad hoc clients.
- Do not describe an unavailable or degraded data source as clean, safe, or successfully checked. Preserve enough status information for callers to distinguish an empty result from a failed or incomplete query.
- Do not introduce automatic containment, destructive actions, or changes to monitored systems as an incidental side effect. Any behavior that changes systems must be explicit, permission-gated, auditable, documented, and tested.

### Tests

Tests should be deterministic, focused, and safe to run repeatedly.

- Add a regression test for each bug fix when practical.
- Prefer mocks, fixtures, and synthetic data over live services, real threat artifacts, or real personal information.
- Test important boundary conditions and failure paths, not only the happy path.
- Do not make network requests to third-party services or production infrastructure from ordinary unit tests.
- Keep fixtures minimal and free of credentials, tokens, private keys, personal data, and confidential incident details.
- When changing configuration or access control, test defaults, invalid configuration, and both permitted and denied cases as appropriate.

## Security and Privacy Requirements

Security and privacy are core project requirements, not optional cleanup work.

- Never commit passwords, API keys, access tokens, private keys, session cookies, or populated production configuration files.
- Never add real incident payloads, personal data, or confidential indicators to public tests or documentation without explicit authorization and suitable sanitization.
- Preserve redaction, audit logging, authentication, read-only defaults, permission checks, and tool-gating behavior.
- Do not weaken authentication, authorization, input limits, redaction, or audit controls merely to make a workflow easier to use.
- Keep write-capable functionality explicitly gated by the project's authorization model. Missing or invalid permission must not silently grant access.
- Avoid logging secrets or entire sensitive payloads. Logs should provide useful diagnostic context while minimizing exposure.
- Use only systems and data that you are authorized to access and test.

If a proposed change affects trust boundaries, permissions, data disclosure, outbound network access, or host execution, describe the threat model and safeguards in the pull request.

## Documentation Changes

Update documentation whenever a change affects installation, configuration, command-line behavior, tool schemas, permissions, output formats, dependencies, operational workflows, or troubleshooting.

Documentation should:

- Use copyable commands with safe placeholders instead of real credentials or sensitive hostnames.
- Identify optional dependencies and external-service requirements clearly.
- Distinguish tested behavior from assumptions or recommendations.
- Keep examples consistent with the implementation and current environment-variable names.
- Avoid promising that an integration, tool, or mitigation works when it has not been verified.

Prefer updating the existing relevant documentation over adding duplicate guidance in several places.

## Commit and Pull Request Workflow

### Branches and commits

Use a descriptive branch name, such as:

```text
fix/redaction-edge-case
feat/alert-correlation-metadata
docs/development-setup
test/threat-intel-timeouts
```

Write clear commit messages in the imperative mood. Prefixes such as `fix:`, `feat:`, `docs:`, `test:`, `refactor:`, or `chore:` are recommended, but consistency and clarity matter more than a particular format.

Examples:

```text
fix: preserve upstream error status in alert lookup
feat: add metadata to correlation results
test: cover malformed threat-intel responses
docs: clarify local development setup
```

### Open a pull request

1. Create a branch from the latest appropriate base branch.
2. Implement the change and add or update tests and documentation.
3. Run the relevant tests and `python3 check_guardrails.py --strict`.
4. Review the diff and commit only files required for the change.
5. Push the branch to your fork and open a pull request against the upstream repository.

A pull request description should explain:

- **Purpose:** What problem does this solve, or what user-visible behavior changes?
- **Approach:** What changed and why was this approach chosen?
- **Testing:** Which commands were run, and did they pass?
- **Security/operational impact:** Are permissions, redaction, logging, dependencies, network calls, or system behavior affected?
- **Documentation:** Which documentation was updated, or why no update was necessary?
- **Limitations:** What could not be tested, and what follow-up work remains?

### Pull request checklist

Before requesting review, confirm that:

- [ ] The change has a clear scope and purpose.
- [ ] Relevant tests were added or updated.
- [ ] Relevant tests and `python3 check_guardrails.py --strict` were run, and results are reported accurately.
- [ ] Documentation and configuration examples match the implementation.
- [ ] No secrets, sensitive data, temporary files, generated artifacts, or unrelated changes are included.
- [ ] Security controls, read-only defaults, authorization checks, redaction, and audit behavior are preserved.
- [ ] Known limitations and untested paths are disclosed.

Maintainers may ask for changes, additional tests, or a narrower scope before merging. Please keep review discussions constructive and respond to feedback with the relevant technical context.

## Reporting Security Vulnerabilities

**Do not report suspected security vulnerabilities in public issues or pull requests.** Public reports can expose users before a fix is available.

Please contact the project maintainers privately through the security contact published in the repository's README (`csirt@tangerangkota.go.id`). Include a concise description, potential impact, reproduction steps where safe, and any relevant version or commit information. Do not send live credentials or unnecessary personal or incident data. Allow the maintainers an opportunity to investigate before publicly disclosing the issue.

If you are uncertain whether information is sensitive, treat it as sensitive and use the private reporting route.

## License

By contributing, you agree that your contributions may be distributed under the project's existing **BSD 3-Clause License**, as identified by the repository's `LICENSE` file. Do not submit code, documentation, or other material that you do not have the right to contribute.

---

Thank you for contributing to Wazuh MCP Server.
