from abc import ABC, abstractmethod
from typing import Any


class Validatable(ABC):
    @abstractmethod
    def validate(self) -> None:
        pass  # pragma: no cover

    def error_message(
        self, component: str, invalid_fields: dict[str, Any]
    ) -> str:
        errors = "\n".join(
            f"  {field}={value!r}" for field, value in invalid_fields.items()
        )
        return f"{component} contains invalid values:\n{errors}"
