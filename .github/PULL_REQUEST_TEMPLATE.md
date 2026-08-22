## Summary

Describe the problem and the smallest coherent change that solves it.

## Safety and compatibility

State the affected roles, invariants, trust assumptions, permissions, event formats, storage schemas, Bitcoin behavior, and operator workflows. Write "not affected" only for areas you checked.

## Verification

List exact tests and manual checks. Include failure, restart, duplicate, stale-state, and malformed-input cases when relevant.

## Checklist

- [ ] The change is based on the current target branch and contains no unrelated edits.
- [ ] I ran formatting, linting, workspace tests, and relevant integration tests.
- [ ] I reviewed the diff for secrets, credentials, fixed nonces, debug output, panics, and generated files.
- [ ] New behavior fails closed when configuration, authorization, proof, state, or backend checks fail.
- [ ] I added tests for invalid and interrupted paths where relevant.
- [ ] I updated the changelog and operator, API, configuration, security, or threat-model documentation where relevant.
- [ ] I have the right to submit this work under Apache-2.0 and preserved required third-party notices.
- [ ] This pull request does not disclose a security vulnerability. I used the private reporting route for any such issue.

## Release note

Write one concise operator-facing line, or explain why no release note is needed.
