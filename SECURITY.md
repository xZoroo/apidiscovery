# Security Policy

This project is a browser extension for authorized security testing. This policy covers
vulnerabilities in the extension's own code (e.g. something that would let a website the extension
merely observes escalate beyond passive observation) — not how you use the tool against a target.

## Supported versions

There are no released versions yet; security fixes land on `main`. Once tagged releases exist,
only the latest release is supported.

## Reporting a vulnerability

Please report vulnerabilities privately using
[GitHub's private vulnerability reporting](../../security/advisories/new) for this repository
(Security tab → "Report a vulnerability"), rather than opening a public issue.

Include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal test page or extension build is ideal).
- The browser and extension build/commit you tested against.

You should get an initial response within a few days. Please allow a reasonable amount of time to
fix the issue before any public disclosure.

## Scope

In scope: the extension's own code (`entrypoints/`, `src/`) — memory-safety-style issues aren't
applicable here (it's TypeScript/DOM), but things like the message bridge between the injected
page script and the extension, permission scoping, and data handling are all fair game.

Out of scope: vulnerabilities in websites you use this tool to test, and the inherent, documented
capabilities of the Repeater/Confirmation-tests features (they are designed to send real,
user-edited requests to whatever site is open — see the README's "Security testing features" and
"Permissions" sections). If you believe one of those features behaves in a way its documentation
doesn't disclose, that is in scope.
