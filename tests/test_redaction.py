from bugbounty_scout.redaction import redact_text


def test_redacts_authorization_jwt_and_cookie() -> None:
    source = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature\n"
        "Cookie: session=synthetic-session-value; theme=dark"
    )
    result = redact_text(source)
    assert "synthetic-session-value" not in result
    assert "eyJhbGci" not in result
    assert "Authorization: Bearer <redacted-token>" in result
    assert "Cookie: <redacted-cookie>" in result


def test_redacts_key_values_email_phone_and_session() -> None:
    source = (
        "api_key=not-a-real-secret\n"
        "session_id: fake-session\n"
        "owner=researcher@example.test\n"
        "phone=(202) 555-0142"
    )
    result = redact_text(source)
    assert "not-a-real-secret" not in result
    assert "fake-session" not in result
    assert "researcher@example.test" not in result
    assert "(202) 555-0142" not in result
