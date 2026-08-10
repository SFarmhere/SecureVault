"""SecureVault - Конфиденциальные вычисления (SEV/TDX).

Программные модели аттестации доверенного окружения Intel TDX
и AMD SEV/SEV-SNP.
"""

from securevault.security.confidential_computing.sev_attestation import (  # noqa: F401
    SevAttestation,
    SevError,
)
from securevault.security.confidential_computing.tdx_attestation import (  # noqa: F401
    TdxAttestation,
    TdxError,
)

__all__ = ["SevAttestation", "SevError", "TdxAttestation", "TdxError"]
