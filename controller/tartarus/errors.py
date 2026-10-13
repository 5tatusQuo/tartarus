class TartarusError(Exception):
    """An expected, safely reportable controller failure."""


class ApprovalRequired(TartarusError):
    """A mutating or destructive action was not approved."""


class AuthenticationRequired(TartarusError):
    """The operator must reconnect an external AI account before work continues."""
