# Cross-user invoice metadata is exposed

## Vulnerability Summary

A standard synthetic test user can read invoice metadata owned by another synthetic test user.

## Technical Details

idor_bola

## Steps to Reproduce

1. Sign in with authorized synthetic test account A.
2. Request the invoice identifier owned by authorized synthetic test account B.
3. Observe account B invoice metadata in the response.

## Business Impact

Cross-user invoice metadata, including billing state, is disclosed.

## Remediation

Enforce object ownership checks on every invoice lookup.

## Attachments

- `fixtures/submit/fake_attachment_request.txt` — Redacted request
- `fixtures/submit/fake_attachment_response.txt` — Redacted response
- `fixtures/submit/does-not-exist.txt` — Missing optional attachment

## Additional Notes

Synthetic local fixture; manual validation is required.

Review program rules manually before submission.

Synthetic example.test assets only.
