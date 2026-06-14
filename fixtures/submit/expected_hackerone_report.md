# Cross-user invoice metadata is exposed

## Summary

A standard synthetic test user can read invoice metadata owned by another synthetic test user.

## Steps to Reproduce

1. Sign in with authorized synthetic test account A.
2. Request the invoice identifier owned by authorized synthetic test account B.
3. Observe account B invoice metadata in the response.

## Impact

Cross-user invoice metadata, including billing state, is disclosed.

## Supporting Material / References

Redacted request and response show the object identifier and returned metadata.

## Suggested Remediation

Enforce object ownership checks on every invoice lookup.

## Notes

Synthetic local fixture; manual validation is required.

Review program rules manually before submission.

Synthetic example.test assets only.
