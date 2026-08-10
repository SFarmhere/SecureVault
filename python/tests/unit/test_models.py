"""SecureVault - Модульные тесты моделей БД."""

from securevault.db.models import AuditRecord, UserRecord


def test_audit_record_to_dict_roundtrip():
    rec = AuditRecord(
        entry_id="e1",
        timestamp="2024-01-01T00:00:00Z",
        user_id="u1",
        action="encrypt",
        result="success",
        details={"file": "a.txt"},
    )
    data = rec.to_dict()
    assert data["action"] == "encrypt"
    restored = AuditRecord.from_db_row(data)
    assert restored.entry_id == "e1"
    assert restored.details["file"] == "a.txt"
    assert restored.to_db_dict()["entry_id"] == "e1"


def test_user_record_roundtrip():
    u = UserRecord(user_id="u1", username="alice", roles=["admin"], mfa_enabled=True)
    row = u.to_db_dict()
    assert row["roles"] == '["admin"]'
    restored = UserRecord.from_db_row(row)
    assert restored.roles == ["admin"]
    assert restored.mfa_enabled is True


def test_create_table_sql_nonempty():
    assert "CREATE TABLE" in AuditRecord.create_table_sql()
    assert "CREATE TABLE" in UserRecord.create_table_sql()
