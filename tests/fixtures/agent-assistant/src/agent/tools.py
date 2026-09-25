"""Fixture touchpoint for control.ticket-confirmation."""


def create_ticket(summary: str, confirmed: bool) -> bool:
    if not confirmed:
        return False
    return True
