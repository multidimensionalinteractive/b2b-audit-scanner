# B2B Security Header Audit Report

**URLs scanned:** 1
**Generated:** 2026-07-27 04:09:23 UTC

## Summary

- D: 1 URL(s)

## https://stripe.com

**Grade:** D | **Score:** 46/100
**Status Code:** 200 | **Response Time:** 0.636s

### Header Checks

| Header | Required | Status | Value |
|--------|----------|--------|-------|
| Strict-Transport-Security | Yes | PASS | max-age=63072000; includeSubDomains; preload |
| Content-Security-Policy | Yes | PASS | base-uri 'none'; child-src 'none'; connect-src https://c.inc... |
| X-Content-Type-Options | Yes | PASS | nosniff |
| X-Frame-Options | Yes | WARN | SAMEORIGIN |
| Cache-Control | No | SKIP |  |
| Permissions-Policy | Yes | FAIL |  |
| Referrer-Policy | Yes | PASS | no-referrer-when-downgrade |
| Cross-Origin-Opener-Policy | Yes | PASS | same-origin-allow-popups; report-to="wsp_coop" |
| Cross-Origin-Resource-Policy | No | SKIP |  |
| Cross-Origin-Embedder-Policy | No | SKIP |  |
| Public-Key-Pins | No | SKIP |  |
| X-XSS-Protection | No | SKIP |  |

### FAILURES

- [HIGH] Permissions-Policy is missing

### WARNINGS

- [LOW] X-Frame-Options: SAMEORIGIN

---
