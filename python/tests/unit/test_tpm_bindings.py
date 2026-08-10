"""SecureVault - Модульные тесты TPM measured boot (программная модель)."""

from securevault.security.tpm_measured_boot import TpmMeasuredBoot


def test_extend_and_chain():
    tpm = TpmMeasuredBoot()
    v1 = tpm.extend(0, b"kernel")
    v2 = tpm.extend(0, b"initrd")
    assert len(v2) == 64
    assert v1 != v2


def test_verify_matches():
    tpm = TpmMeasuredBoot()
    expected = tpm.extend(4, b"measure")
    assert tpm.verify(4, expected) is True
    assert tpm.verify(4, "00" * 32) is False


def test_unmeasured_returns_none():
    tpm = TpmMeasuredBoot()
    assert tpm.get(10) is None
    assert tpm.verify(10, "00" * 32) is False


def test_reset():
    tpm = TpmMeasuredBoot()
    val = tpm.extend(1, b"a")
    assert tpm.get(1) == val
    tpm.reset(1)
    assert tpm.get(1) is None


def test_manifest_integrity():
    tpm = TpmMeasuredBoot()
    pcr0 = tpm.extend(0, b"stage")
    assert tpm.integrity_match({0: pcr0}) is True
    assert tpm.integrity_match({0: "00" * 32}) is False
