"""Priv-Audit check registry."""

from privaudit.checks.suid import SuidCheck
from privaudit.checks.sudo import SudoCheck
from privaudit.checks.filesystem import FilesystemCheck
from privaudit.checks.ssh import SshCheck
from privaudit.checks.capabilities import CapabilitiesCheck
from privaudit.checks.persistence import PersistenceCheck

ALL_CHECKS = [
    SuidCheck,
    SudoCheck,
    FilesystemCheck,
    SshCheck,
    CapabilitiesCheck,
    PersistenceCheck,
]
