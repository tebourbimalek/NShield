# Security policy

## Supported versions

Only the latest commit on `main` is supported. There are no LTS branches.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Email the
maintainer (see the GitHub profile) with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The version / commit you tested against.

You will get an acknowledgement within 7 days and a fix or mitigation plan
within 30 days where possible.

## Scope notes

NShield is a *local network control tool*. The threat model assumes:

- The machine running NShield is trusted and under the user's control.
- The LAN is the user's own network (see the legal warning).
- The phone-access passcode is a convenience gate, not a security boundary:
  it is a short code sent over plain HTTP on the LAN. Repeated wrong
  attempts from one address are throttled (5 per minute) to slow guessing.

Known limitations that are **not** considered vulnerabilities:

- ARP/NDP spoofing itself is the intended feature, not a bug.
- The 4-digit phone passcode is brute-forceable by anyone on the LAN.
- There is no TLS on the local HTTP server.

Contributions that harden the phone path (TLS, rate limiting, longer
passcodes) are very welcome.
