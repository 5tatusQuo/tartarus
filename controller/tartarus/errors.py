class TartarusError(Exception):
    """An expected, safely reportable controller failure."""


class ApprovalRequired(TartarusError):
    """A mutating or destructive action was not approved."""
