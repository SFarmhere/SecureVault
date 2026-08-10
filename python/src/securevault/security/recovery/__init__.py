"""SecureVault - Восстановление доступа (рольsecurity.recovery).

Сценарии экстренного и социального восстановления (Shamir), а также
CLI-интерфейс к ним.
"""

from securevault.security.recovery.cli_recovery import CliRecovery  # noqa: F401
from securevault.security.recovery.emergency_recovery import (  # noqa: F401
    EmergencyRecovery,
    EmergencyRecoveryError,
)
from securevault.security.recovery.social_recovery import (  # noqa: F401
    SocialRecovery,
    SocialRecoveryError,
)

__all__ = [
    "EmergencyRecovery",
    "EmergencyRecoveryError",
    "SocialRecovery",
    "SocialRecoveryError",
    "CliRecovery",
]
