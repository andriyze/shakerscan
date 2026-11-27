"""Worker-private, sealed HTTP probe configuration; never an API or queue payload."""
import fcntl
import os


class HttpxCredentialConfiguration:
    def __init__(self, content: bytes):
        if not isinstance(content, bytes) or not 1 <= len(content) <= 65_536:
            raise ValueError("HTTP probe configuration is invalid")
        if not hasattr(os, "memfd_create") or not hasattr(fcntl, "F_ADD_SEALS"):
            raise ValueError("sealed HTTP probe configuration is unavailable")
        self._fd = os.memfd_create("shakerscan-httpx", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(self._fd, 0o600)
            offset = 0
            while offset < len(content):
                offset += os.write(self._fd, content[offset:])
            os.lseek(self._fd, 0, os.SEEK_SET)
            fcntl.fcntl(self._fd, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        except BaseException:
            self.close()
            raise

    @property
    def descriptor(self):
        if self._fd is None:
            raise ValueError("HTTP probe configuration is closed")
        return self._fd

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __repr__(self):
        return "HttpxCredentialConfiguration(values_visible=False)"
