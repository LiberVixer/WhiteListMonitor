from datetime import datetime
from html import escape
from time import monotonic

from apscheduler.schedulers.background import BackgroundScheduler
from PyQt6.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QCloseEvent, QIcon, QPainter, QPixmap, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QSystemTrayIcon,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .database import Database
from .network_check import CheckResult, detect_network_status
from .settings_dialog import SettingsDialog
from .settings_store import AppSettings, save_settings
from .status import STATUS_LABELS, NetworkStatus
from .vpn_worker import VPNWorker
from .vpn_extended_rating import ExtendedRatingWorker


TRAY_DOUBLE_CLICK_SECONDS = 0.45


class NetworkCheckWorker(QObject):
    finished = pyqtSignal(object)

    def __init__(self, settings: AppSettings):
        super().__init__()
        self.settings = settings

    def run(self) -> None:
        self.finished.emit(detect_network_status(self.settings))


class StaticRatingRecalcWorker(QObject):
    log = pyqtSignal(str)
    html_log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, db: Database):
        super().__init__()
        self.db = db

    def run(self) -> None:
        try:
            self.log.emit("Пересчет S-рейтинга: старт")

            worker = VPNWorker(self.db)
            result = worker.recalculate_static_ratings_in_db()

            self.log.emit(
                "Пересчет S-рейтинга завершен: "
                f"всего={result['total']}, "
                f"CANDIDATE={result['candidate']}, "
                f"BAD={result['bad']}, "
                f"ошибок разбора={result['parse_failed']}, "
                f"SNI whitelist base-доменов={result['whitelist_domains']}"
            )
            self.html_log.emit(self.format_static_rating_stats(result))
        except Exception as exc:
            self.log.emit(f"Ошибка пересчета S-рейтинга: {exc}")
        finally:
            self.finished.emit()

    def format_static_rating_stats(self, result: dict[str, int]) -> str:
        rows = [
            ("Всего серверов в базе:", result["total"], "#d6e4ff"),
            ("|- Неподходящих:", result["bad"], "#ff9b9b"),
            ("|- Подходящих:", result["candidate"], "#9be7a8"),
            ("&nbsp;&nbsp;&nbsp;|- Низкий S-рейтинг:", result["low_rating"], "#f6b26b"),
            ("&nbsp;&nbsp;&nbsp;|- Средний S-рейтинг:", result["medium_rating"], "#ffd966"),
            ("&nbsp;&nbsp;&nbsp;|- Высокий S-рейтинг:", result["high_rating"], "#93c47d"),
            ("&nbsp;&nbsp;&nbsp;|- Топовый S-рейтинг:", result["top_rating"], "#6fa8dc"),
        ]

        lines = []

        for label, value, color in rows:
            lines.append(
                f'<div style="font-weight:700;color:{color};">'
                f"{label} {value}"
                "</div>"
            )

        return "".join(lines)


class MainWindow(QMainWindow):
    scheduler_vpn_requested = pyqtSignal()

    def __init__(self, settings: AppSettings, db: Database):
        super().__init__()

        self.settings = settings
        self.db = db
        self.current_status = NetworkStatus.UNKNOWN

        self.check_thread: QThread | None = None
        self.check_worker: NetworkCheckWorker | None = None

        self.vpn_thread: QThread | None = None
        self.vpn_worker: VPNWorker | None = None

        self.recalc_thread: QThread | None = None
        self.recalc_worker: StaticRatingRecalcWorker | None = None

        self.ext_thread: QThread | None = None
        self.ext_worker: ExtendedRatingWorker | None = None

        self.last_tray_trigger_at = 0.0

        self.setWindowTitle("White List Monitor")
        self.resize(850, 560)

        self.status_label = QLabel("Текущий статус: Неизвестно")
        self.last_check_label = QLabel("Последняя проверка: не выполнялась")
        self.details_label = QLabel("")

        self.console = QTextEdit()
        self.console.setReadOnly(True)

        self.check_button = QPushButton("Проверить сейчас")
        self.vpn_button = QPushButton("Запустить VPN-скрипт")
        self.recalc_rating_button = QPushButton("Пересчитать S-рейтинг в базе")
        self.ext_rating_button = QPushButton("Запустить e-рейтинг портов")
        self.settings_button = QPushButton("Настройки")

        self.check_button.clicked.connect(self.run_network_check)
        self.vpn_button.clicked.connect(self.run_vpn_worker)
        self.recalc_rating_button.clicked.connect(self.run_static_rating_recalc_worker)
        self.ext_rating_button.clicked.connect(self.run_extended_rating_worker)
        self.settings_button.clicked.connect(self.open_settings)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(self.status_label)
        layout.addWidget(self.last_check_label)
        layout.addWidget(self.details_label)
        layout.addWidget(self.console, stretch=1)
        layout.addWidget(self.check_button)
        layout.addWidget(self.vpn_button)
        layout.addWidget(self.recalc_rating_button)
        layout.addWidget(self.ext_rating_button)
        layout.addWidget(self.settings_button)
        self.setCentralWidget(central)

        toolbar = QToolBar("Главная")
        self.addToolBar(toolbar)
        toolbar.addAction(self.make_action("Проверить", self.run_network_check))
        toolbar.addAction(self.make_action("VPN-скрипт", self.run_vpn_worker))
        toolbar.addAction(self.make_action("S-рейтинг", self.run_static_rating_recalc_worker))
        toolbar.addAction(self.make_action("e-рейтинг", self.run_extended_rating_worker))
        toolbar.addAction(self.make_action("Настройки", self.open_settings))

        self.tray = QSystemTrayIcon(self)
        self.tray.setContextMenu(self.build_tray_menu())
        self.tray.activated.connect(self.on_tray_activated)

        self.update_status(NetworkStatus.UNKNOWN, "Ожидание первой проверки")
        self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.run_network_check)
        self.restart_timer()

        self.scheduler = BackgroundScheduler()
        self.scheduler_vpn_requested.connect(self.run_vpn_worker)
        self.restart_scheduler()

        QTimer.singleShot(500, self.run_network_check)

    def make_action(self, title: str, callback) -> QAction:
        action = QAction(title, self)
        action.triggered.connect(callback)
        return action

    def build_tray_menu(self) -> QMenu:
        menu = QMenu()

        show_action = menu.addAction("Показать окно")
        show_action.triggered.connect(self.show_normal)

        check_action = menu.addAction("Проверить сейчас")
        check_action.triggered.connect(self.run_network_check)

        vpn_action = menu.addAction("Запустить VPN-скрипт")
        vpn_action.triggered.connect(self.run_vpn_worker)

        recalc_action = menu.addAction("Пересчитать S-рейтинг")
        recalc_action.triggered.connect(self.run_static_rating_recalc_worker)

        ext_action = menu.addAction("Запустить e-рейтинг портов")
        ext_action.triggered.connect(self.run_extended_rating_worker)

        settings_action = menu.addAction("Настройки")
        settings_action.triggered.connect(self.open_settings)

        menu.addSeparator()

        quit_action = menu.addAction("Выход")
        quit_action.triggered.connect(self.quit_application)

        return menu

    def show_normal(self) -> None:
        self.showNormal()
        self.setWindowState(
            (self.windowState() & ~Qt.WindowState.WindowMinimized)
            | Qt.WindowState.WindowActive
        )
        self.raise_()
        self.activateWindow()
        QTimer.singleShot(100, self.raise_)
        QTimer.singleShot(100, self.activateWindow)

    def on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.last_tray_trigger_at = 0.0
            self.show_normal()
            return

        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            now = monotonic()

            if now - self.last_tray_trigger_at <= TRAY_DOUBLE_CLICK_SECONDS:
                self.last_tray_trigger_at = 0.0
                self.show_normal()
                return

            self.last_tray_trigger_at = now

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.settings.minimize_to_tray and self.tray.isVisible():
            event.ignore()
            self.hide()
            self.log("Окно свернуто в трей")
            return

        self.shutdown_scheduler()
        event.accept()

    def quit_application(self) -> None:
        self.shutdown_scheduler()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def shutdown_scheduler(self) -> None:
        try:
            if hasattr(self, "scheduler") and self.scheduler.running:
                self.scheduler.shutdown(wait=False)
        except Exception:
            pass

    def log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"{stamp} {message}")

    def log_html(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(
            f'<span style="color:#888888;">{escape(stamp)}</span> {message}'
        )

    def restart_timer(self) -> None:
        interval_ms = max(1, self.settings.check_interval_minutes) * 60 * 1000
        self.timer.start(interval_ms)
        self.log(f"Интервал проверки сети: {self.settings.check_interval_minutes} мин.")

    def restart_scheduler(self) -> None:
        if self.scheduler.running:
            self.scheduler.remove_all_jobs()

        self.scheduler.add_job(
            self.scheduler_vpn_requested.emit,
            trigger="cron",
            hour=self.settings.scheduler_hour,
            minute=self.settings.scheduler_minute,
            id="vpn_worker",
            replace_existing=True,
        )

        if not self.scheduler.running:
            self.scheduler.start()

        self.log(
            "Планировщик VPN-скрипта: "
            f"час={self.settings.scheduler_hour}, "
            f"минута={self.settings.scheduler_minute}"
        )

    def run_network_check(self) -> None:
        if self.check_thread and self.check_thread.isRunning():
            self.log("Проверка сети уже выполняется")
            return

        self.log("Проверка сети")

        self.check_thread = QThread()
        self.check_worker = NetworkCheckWorker(self.settings)

        self.check_worker.moveToThread(self.check_thread)

        self.check_thread.started.connect(self.check_worker.run)
        self.check_worker.finished.connect(self.on_network_check_finished)
        self.check_worker.finished.connect(self.check_thread.quit)
        self.check_worker.finished.connect(self.check_worker.deleteLater)

        self.check_thread.finished.connect(self.check_thread.deleteLater)
        self.check_thread.finished.connect(self.clear_check_worker)

        self.check_thread.start()

    def clear_check_worker(self) -> None:
        self.check_thread = None
        self.check_worker = None

    def on_network_check_finished(self, result: CheckResult) -> None:
        self.update_status(result.status, result.details)

        self.last_check_label.setText(
            "Последняя проверка: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        self.details_label.setText(result.details)
        self.log(STATUS_LABELS.get(result.status, "Неизвестно") + ": " + result.details)

    def update_status(self, status: NetworkStatus, details: str) -> None:
        self.current_status = status

        label = STATUS_LABELS.get(status, "Неизвестно")
        self.status_label.setText(f"Текущий статус: {label}")

        icon = self.make_status_icon(status)

        self.setWindowIcon(icon)
        self.tray.setIcon(icon)
        self.tray.setToolTip(
            f"White List Monitor\n"
            f"Статус: {label}\n"
            f"{details}"
        )

    def make_status_icon(self, status: NetworkStatus) -> QIcon:
        colors = {
            NetworkStatus.FREE_INTERNET: "#22aa44",
            NetworkStatus.WHITELIST_MODE: "#d9a600",
            NetworkStatus.NO_INTERNET: "#cc3333",
            NetworkStatus.ROUTER_DOWN: "#222222",
            NetworkStatus.UNKNOWN: "#777777",
        }

        symbols = {
            NetworkStatus.FREE_INTERNET: "G",
            NetworkStatus.WHITELIST_MODE: "W",
            NetworkStatus.NO_INTERNET: "!",
            NetworkStatus.ROUTER_DOWN: "R",
            NetworkStatus.UNKNOWN: "?",
        }

        pix = QPixmap(64, 64)
        pix.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        painter.setBrush(QColor(colors.get(status, "#777777")))
        painter.setPen(QPen(QColor("#333333"), 2))
        painter.drawEllipse(4, 4, 56, 56)

        painter.setPen(QColor("#ffffff"))

        font = painter.font()
        font.setBold(True)
        font.setPointSize(26)
        painter.setFont(font)

        painter.drawText(
            pix.rect(),
            Qt.AlignmentFlag.AlignCenter,
            symbols.get(status, "?"),
        )

        painter.end()

        return QIcon(pix)

    def open_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self.db, self)

        if dialog.exec():
            self.settings = dialog.collect_settings()
            self.db.replace_subscribes(dialog.collect_subscribes())
            save_settings(self.settings)

            self.restart_timer()
            self.restart_scheduler()

            self.log("Настройки сохранены")
            self.run_network_check()

    def run_vpn_worker(self) -> None:
        if self.vpn_thread and self.vpn_thread.isRunning():
            self.log("VPN-скрипт уже выполняется")
            return

        self.log("Запуск VPN-скрипта")

        self.vpn_thread = QThread()
        self.vpn_worker = VPNWorker(self.db)

        self.vpn_worker.moveToThread(self.vpn_thread)

        self.vpn_thread.started.connect(self.vpn_worker.run)
        self.vpn_worker.log.connect(self.log)
        self.vpn_worker.finished.connect(self.vpn_thread.quit)
        self.vpn_worker.finished.connect(self.vpn_worker.deleteLater)

        self.vpn_thread.finished.connect(self.vpn_thread.deleteLater)
        self.vpn_thread.finished.connect(self.clear_vpn_worker)

        self.vpn_thread.start()

    def clear_vpn_worker(self) -> None:
        self.vpn_thread = None
        self.vpn_worker = None

    def run_static_rating_recalc_worker(self) -> None:
        if self.recalc_thread and self.recalc_thread.isRunning():
            self.log("Пересчет S-рейтинга уже выполняется")
            return

        if self.vpn_thread and self.vpn_thread.isRunning():
            self.log("Пересчет S-рейтинга не запущен: VPN-скрипт уже выполняется")
            return

        if self.ext_thread and self.ext_thread.isRunning():
            self.log("Пересчет S-рейтинга не запущен: e-рейтинг уже выполняется")
            return

        self.recalc_thread = QThread()
        self.recalc_worker = StaticRatingRecalcWorker(self.db)

        self.recalc_worker.moveToThread(self.recalc_thread)

        self.recalc_thread.started.connect(self.recalc_worker.run)
        self.recalc_worker.log.connect(self.log)
        self.recalc_worker.html_log.connect(self.log_html)
        self.recalc_worker.finished.connect(self.recalc_thread.quit)
        self.recalc_worker.finished.connect(self.recalc_worker.deleteLater)

        self.recalc_thread.finished.connect(self.recalc_thread.deleteLater)
        self.recalc_thread.finished.connect(self.clear_static_rating_recalc_worker)

        self.recalc_thread.start()

    def clear_static_rating_recalc_worker(self) -> None:
        self.recalc_thread = None
        self.recalc_worker = None

    def run_extended_rating_worker(self) -> None:
        if self.ext_thread and self.ext_thread.isRunning():
            self.log("e-рейтинг уже выполняется")
            return

        if self.current_status in {NetworkStatus.NO_INTERNET, NetworkStatus.ROUTER_DOWN}:
            self.log("e-рейтинг не запущен: нет сети или недоступен роутер")
            return

        mode_label = STATUS_LABELS.get(self.current_status, "Неизвестно")
        self.log(f"Запуск e-рейтинга портов. Текущий режим: {mode_label}")

        self.ext_thread = QThread()
        self.ext_worker = ExtendedRatingWorker(
            db=self.db,
            mode=self.current_status,
            max_workers=self.settings.extended_rating_max_workers,
            top_limit=self.settings.extended_rating_top_limit,
            timeout_seconds=self.settings.extended_rating_timeout_seconds,
            retries=self.settings.extended_rating_retries,
            submit_delay_ms=self.settings.extended_rating_submit_delay_ms,
            retry_delay_ms=self.settings.extended_rating_retry_delay_ms,
        )

        self.ext_worker.moveToThread(self.ext_thread)

        self.ext_thread.started.connect(self.ext_worker.run)
        self.ext_worker.log.connect(self.log)
        self.ext_worker.finished.connect(self.ext_thread.quit)
        self.ext_worker.finished.connect(self.ext_worker.deleteLater)

        self.ext_thread.finished.connect(self.ext_thread.deleteLater)
        self.ext_thread.finished.connect(self.clear_extended_rating_worker)

        self.ext_thread.start()

    def clear_extended_rating_worker(self) -> None:
        self.ext_thread = None
        self.ext_worker = None
