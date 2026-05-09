from __future__ import annotations


def confirm_action(message: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    print()
    print(message)
    response = input("Continue? [y/N]: ").strip().lower()
    return response in {"y", "yes"}
