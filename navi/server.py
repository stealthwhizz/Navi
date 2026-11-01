"""Reserve the dashboard's actual port before starting FastAPI."""
from contextlib import contextmanager
import errno
import socket


@contextmanager
def dashboard_socket(host, port=None):
    if port is not None and (type(port) is not int or not 0 <= port <= 65535):
        raise ValueError("Dashboard port must be between 0 and 65535 (0 selects an available port).")
    candidates = range(8080, 8090) if port is None else [port]
    for candidate in candidates:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, candidate))
            listener.listen(128)
        except OSError as error:
            listener.close()
            if error.errno == errno.EADDRINUSE:
                if port is None: continue
                raise ValueError(f"Dashboard port {port} is already in use. Choose --port 8081 or --port 0 for an available port.") from error
            raise ValueError(f"Cannot bind dashboard on {host}:{candidate} ({error.strerror or type(error).__name__}).") from error
        try:
            yield listener
        finally:
            listener.close()
        return
    raise ValueError("Dashboard ports 8080–8089 are occupied. Use --port 0 to select an available port.")
