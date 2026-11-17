"""Private execution artifacts with streaming redaction of injected values."""
import os
from contextlib import contextmanager


class SecretWriter:
    def __init__(self, stream, secrets):
        self.stream = stream
        self.secrets = sorted({s.encode() for s in secrets if s}, key=len, reverse=True)
        self.pending = b''
        self.tail = max(map(len, self.secrets), default=1) - 1

    def write(self, data, *, final=False):
        data = self.pending + data
        end = len(data) if final else max(0, len(data) - self.tail)
        index, safe = 0, bytearray()
        while index < end:
            match = next((secret for secret in self.secrets if data.startswith(secret, index)), None)
            if match:
                safe.extend(b'[credential redacted]'); index += len(match)
            else:
                safe.append(data[index]); index += 1
        self.pending = data[index:]
        self.stream.write(safe)

    def flush(self):
        self.stream.flush()


@contextmanager
def protected_output(path, secrets=()):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as raw:
        stream = SecretWriter(raw, secrets) if secrets else raw
        try:
            yield stream
        finally:
            if secrets:
                stream.write(b'', final=True)
