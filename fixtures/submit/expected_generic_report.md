# Cross-user invoice metadata is exposed

## Summary

A standard synthetic test user can read invoice metadata owned by another synthetic test user.

## Affected asset

- `https://api.example.test/api/invoices/{id}`

## Vulnerability class

idor_bola

## Severity

Medium — Limited cross-user billing metadata disclosure without modification.

## Impact

Cross-user invoice metadata, including billing state, is disclosed.

## Steps to reproduce

1. Sign in with authorized synthetic test account A.
2. Request the invoice identifier owned by authorized synthetic test account B.
3. Observe account B invoice metadata in the response.

## Expected behavior

The service should deny access to invoices owned by another user.

## Actual behavior

The service returns the other synthetic user's invoice metadata.

## Evidence

Redacted request and response show the object identifier and returned metadata.

## Remediation

Enforce object ownership checks on every invoice lookup.

## Notes / limitations

Synthetic local fixture; manual validation is required.

Review program rules manually before submission.

Synthetic example.test assets only.
