from abc import ABC, abstractmethod
from typing import Any


class Validatable(ABC):
    @abstractmethod
    def validate(self) -> None:
        pass  # pragma: no cover

    def error_message(
        self, component: str, invalid_fields: dict[str, Any]
    ) -> str:
        return (
            f"{component} contains invalid values:\n"
            f"{self.__errors(invalid_fields)}"
        )

    def __errors(self, invalid_fields: dict[str, Any]) -> str:
        return "\n".join(
            f"  {field}={value!r}" for field, value in invalid_fields.items()
        )
