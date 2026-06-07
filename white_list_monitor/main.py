import sys

from PyQt6.QtWidgets import QApplication

from . import __version__
from .database import Database
from .main_window import MainWindow
from .settings_store import load_settings


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("White List Monitor")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("LiberVixer")
    app.setQuitOnLastWindowClosed(False)

    settings = load_settings()
    db = Database()
    window = MainWindow(settings, db)
    if not settings.start_minimized:
        window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
