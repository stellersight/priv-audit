"""Base check interface for Priv-Audit analyzers."""

from abc import ABC, abstractmethod
from typing import List
from privaudit.models import Finding


class BaseCheck(ABC):
    """Abstract base class that all auditing modules implement."""

    check_id: str = "BASE"
    name: str = "Base Check"
    description: str = "Base check interface"

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute the audit check and return any discovered findings."""
        pass
