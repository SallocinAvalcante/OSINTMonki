class Finding:
    def __init__(self, source, type, value, severity, meta=None):
        self.source = source
        self.type = type
        self.value = value
        self.severity = severity
        self.meta = meta or {}

    def __str__(self):
        return f"[{self.severity}] ({self.source}) {self.type}: {self.value}"