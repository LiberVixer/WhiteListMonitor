import csv
import re
from pathlib import Path

import requests
from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHeaderView,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .database import Database, Subscribe
from .settings_store import (
    AppSettings,
    DEFAULT_OPEN_INTERNET_CHECK_URLS,
    DEFAULT_WHITELIST_CHECK_URLS,
)
from .sni_domains import (
    compact_sni_whitelist,
    ensure_sni_domain_pool_table,
    ensure_whitelist_sni_table,
    list_sni_domain_pool,
    merge_sni_domain_rows,
    normalize_sni_domain,
    set_whitelist_sni_enabled,
    sync_sni_domain_pool_from_servers,
)


class SniDomainPoolSyncWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(object, object)

    def __init__(self, db_path: Path):
        super().__init__()
        self.db_path = db_path

    def run(self) -> None:
        try:
            db = Database(self.db_path)
            result = sync_sni_domain_pool_from_servers(
                db,
                progress_callback=self.progress.emit,
            )
            self.progress.emit(98)
            rows = list_sni_domain_pool(db)
            self.progress.emit(100)
            self.finished.emit(result, rows)
        except Exception as exc:
            self.finished.emit(exc, [])


class SniWhitelistDialog(QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)

        self.db = db
        self.last_sni_duplicate_removed = 0

        self.setWindowTitle("SNI whitelist")
        self.resize(900, 600)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Вкл", "SNI домен", "Комментарий"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(2, 260)

        add_btn = QPushButton("Добавить")
        del_btn = QPushButton("Удалить")

        add_btn.clicked.connect(self.add_empty_row)
        del_btn.clicked.connect(self.delete_selected_rows)

        table_buttons = QHBoxLayout()
        table_buttons.addWidget(add_btn)
        table_buttons.addWidget(del_btn)
        table_buttons.addStretch(1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.save_and_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table)
        layout.addLayout(table_buttons)
        layout.addWidget(buttons)

        self.ensure_sni_table()
        self.load_domains()

    def ensure_sni_table(self) -> None:
        ensure_whitelist_sni_table(self.db)

    def load_domains(self) -> None:
        self.table.setRowCount(0)
        compact_sni_whitelist(self.db)

        with self.db.connect() as con:
            rows = con.execute(
                """
                SELECT domain, enabled, comment
                FROM whitelist_sni
                ORDER BY enabled DESC, domain ASC
                """
            ).fetchall()

        for domain, enabled, comment in rows:
            self.add_row(
                domain=str(domain or ""),
                enabled=bool(enabled),
                comment=str(comment or ""),
            )

    def add_empty_row(self) -> None:
        self.add_row(domain="", enabled=True, comment="")

    def add_row(self, domain: str, enabled: bool, comment: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        enabled_item = QTableWidgetItem()
        enabled_item.setFlags(
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )
        enabled_item.setCheckState(
            Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked
        )
        enabled_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        domain_item = QTableWidgetItem(domain)
        domain_item.setToolTip(domain)

        comment_item = QTableWidgetItem(comment)

        self.table.setItem(row, 0, enabled_item)
        self.table.setItem(row, 1, domain_item)
        self.table.setItem(row, 2, comment_item)

    def delete_selected_rows(self) -> None:
        rows = sorted(
            {index.row() for index in self.table.selectedIndexes()},
            reverse=True,
        )

        for row in rows:
            self.table.removeRow(row)

    def collect_domains(self) -> list[tuple[str, int, str]]:
        rows = []
        invalid = []

        for row in range(self.table.rowCount()):
            enabled_item = self.table.item(row, 0)
            domain_item = self.table.item(row, 1)
            comment_item = self.table.item(row, 2)

            raw_domain = domain_item.text().strip() if domain_item else ""
            comment = comment_item.text().strip() if comment_item else ""

            if not raw_domain:
                continue

            domain = normalize_sni_domain(raw_domain)

            if not domain:
                invalid.append(raw_domain)
                continue

            enabled = (
                enabled_item.checkState() == Qt.CheckState.Checked
                if enabled_item
                else True
            )
            rows.append((domain, 1 if enabled else 0, comment))

        if invalid:
            raise ValueError(
                "Некорректные SNI-домены:\n" + "\n".join(invalid[:20])
            )

        merged_rows = merge_sni_domain_rows(rows)
        self.last_sni_duplicate_removed = len(rows) - len(merged_rows)

        return merged_rows

    def save_and_accept(self) -> None:
        try:
            rows = self.collect_domains()
        except ValueError as exc:
            QMessageBox.warning(self, "SNI whitelist", str(exc))
            return

        with self.db.connect() as con:
            con.execute("DELETE FROM whitelist_sni")
            con.executemany(
                """
                INSERT INTO whitelist_sni (domain, enabled, comment)
                VALUES (?, ?, ?)
                """,
                rows,
            )

        compacted = compact_sni_whitelist(self.db)
        QMessageBox.information(
            self,
            "SNI whitelist",
            f"Сохранено доменов: {compacted['after']}\n"
            f"Дубликатов удалено: "
            f"{self.last_sni_duplicate_removed + compacted['removed']}",
        )
        self.accept()


class SniDomainPoolDialog(QDialog):
    def __init__(self, db: Database, parent=None):
        super().__init__(parent)

        self.db = db

        self.setWindowTitle("SNI домены из подписок")
        self.resize(1000, 650)
        self.sync_thread: QThread | None = None
        self.sync_worker: SniDomainPoolSyncWorker | None = None

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["WL", "SNI домен", "Найдено", "Комментарий", "➕", "➖"]
        )
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.cellClicked.connect(self.on_cell_clicked)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 260)
        self.table.setColumnWidth(4, 50)
        self.table.setColumnWidth(5, 50)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.verticalHeader().setMinimumSectionSize(20)

        self.refresh_btn = QPushButton("Обновить из базы")
        self.refresh_btn.clicked.connect(self.sync_and_load_domains)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFixedWidth(180)
        self.progress.setFixedHeight(16)
        self.progress.setTextVisible(True)
        self.progress.hide()

        controls = QHBoxLayout()
        controls.addWidget(self.refresh_btn)
        controls.addWidget(self.progress)
        controls.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(controls)
        layout.addWidget(self.table)
        layout.addWidget(buttons)

        ensure_sni_domain_pool_table(self.db)
        ensure_whitelist_sni_table(self.db)
        self.sync_and_load_domains()

    def sync_and_load_domains(self) -> None:
        if self.sync_thread and self.sync_thread.isRunning():
            return

        self.progress.show()
        self.progress.setValue(0)
        self.refresh_btn.setEnabled(False)
        self.table.setEnabled(False)

        self.sync_thread = QThread()
        self.sync_worker = SniDomainPoolSyncWorker(self.db.path)
        self.sync_worker.moveToThread(self.sync_thread)

        self.sync_thread.started.connect(self.sync_worker.run)
        self.sync_worker.progress.connect(self.progress.setValue)
        self.sync_worker.finished.connect(self.on_sync_finished)
        self.sync_worker.finished.connect(self.sync_thread.quit)
        self.sync_worker.finished.connect(self.sync_worker.deleteLater)
        self.sync_thread.finished.connect(self.sync_thread.deleteLater)
        self.sync_thread.finished.connect(self.clear_sync_worker)

        self.sync_thread.start()

    def on_sync_finished(self, result: object, rows: object) -> None:
        self.progress.setValue(100)

        if isinstance(result, Exception):
            self.progress.hide()
            self.refresh_btn.setEnabled(True)
            self.table.setEnabled(True)
            QMessageBox.warning(
                self,
                "SNI домены из подписок",
                f"Не удалось обновить SNI домены:\n{result}",
            )
            return

        self.load_domains(rows if isinstance(rows, list) else None)
        self.progress.hide()
        self.refresh_btn.setEnabled(True)
        self.table.setEnabled(True)

    def clear_sync_worker(self) -> None:
        self.sync_thread = None
        self.sync_worker = None

    def is_sync_running(self) -> bool:
        return bool(self.sync_thread and self.sync_thread.isRunning())

    def reject(self) -> None:
        if self.is_sync_running():
            QMessageBox.information(
                self,
                "SNI домены из подписок",
                "Дождись завершения загрузки списка.",
            )
            return

        super().reject()

    def closeEvent(self, event) -> None:
        if self.is_sync_running():
            event.ignore()
            return

        super().closeEvent(event)

    def load_domains(self, rows: list[dict[str, object]] | None = None) -> None:
        if rows is None:
            rows = list_sni_domain_pool(self.db)

        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(0)

            for row_data in rows:
                self.add_row(
                    domain=str(row_data["domain"]),
                    found_count=int(row_data["found_count"]),
                    comment=str(row_data["comment"]),
                    whitelist_enabled=bool(row_data["whitelist_enabled"]),
                )
        finally:
            self.table.setUpdatesEnabled(True)

    def add_row(
        self,
        domain: str,
        found_count: int,
        comment: str,
        whitelist_enabled: bool,
    ) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        status_item = QTableWidgetItem("WL" if whitelist_enabled else "")
        domain_item = QTableWidgetItem(domain)
        count_item = QTableWidgetItem(str(found_count))
        comment_item = QTableWidgetItem(comment)
        add_item = QTableWidgetItem("➕")
        remove_item = QTableWidgetItem("➖")

        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        add_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        remove_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        domain_item.setToolTip(domain)
        add_item.setToolTip("Добавить в SNI whitelist")
        remove_item.setToolTip("Удалить из SNI whitelist")
        status_item.setData(Qt.ItemDataRole.UserRole, whitelist_enabled)

        active_add_color = QColor("#157f3b")
        active_remove_color = QColor("#b42318")
        disabled_action_color = QColor("#c0c7cf")

        for item in (
            status_item,
            domain_item,
            count_item,
            comment_item,
            add_item,
            remove_item,
        ):
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

        if whitelist_enabled:
            status_item.setForeground(QColor("#166534"))
            status_font = status_item.font()
            status_font.setBold(True)
            status_item.setFont(status_font)

        if whitelist_enabled:
            add_item.setForeground(disabled_action_color)
            remove_item.setForeground(active_remove_color)
        else:
            add_item.setForeground(active_add_color)
            remove_item.setForeground(disabled_action_color)

        self.table.setItem(row, 0, status_item)
        self.table.setItem(row, 1, domain_item)
        self.table.setItem(row, 2, count_item)
        self.table.setItem(row, 3, comment_item)
        self.table.setItem(row, 4, add_item)
        self.table.setItem(row, 5, remove_item)

    def on_cell_clicked(self, row: int, column: int) -> None:
        if column not in {4, 5}:
            return

        status_item = self.table.item(row, 0)
        domain_item = self.table.item(row, 1)

        if not status_item or not domain_item:
            return

        whitelist_enabled = bool(status_item.data(Qt.ItemDataRole.UserRole))
        domain = domain_item.text().strip()

        if column == 4 and not whitelist_enabled:
            self.add_to_whitelist(domain)
        elif column == 5 and whitelist_enabled:
            self.remove_from_whitelist(domain)

    def add_to_whitelist(self, domain: str) -> None:
        if set_whitelist_sni_enabled(self.db, domain, True):
            self.load_domains()

    def remove_from_whitelist(self, domain: str) -> None:
        if set_whitelist_sni_enabled(self.db, domain, False):
            self.load_domains()


class SettingsDialog(QDialog):
    def __init__(self, settings: AppSettings, db: Database, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Настройки")
        self.resize(1100, 700)

        self.settings = settings
        self.db = db

        self.router_ip = QLineEdit(settings.router_ip)
        self.whitelist_check_urls = QLineEdit(
            self.format_url_list(
                getattr(settings, "whitelist_check_urls", DEFAULT_WHITELIST_CHECK_URLS),
                DEFAULT_WHITELIST_CHECK_URLS,
            )
        )
        self.open_internet_check_urls = QLineEdit(
            self.format_url_list(
                getattr(settings, "open_internet_check_urls", DEFAULT_OPEN_INTERNET_CHECK_URLS),
                DEFAULT_OPEN_INTERNET_CHECK_URLS,
            )
        )
        self.http_timeout = QLineEdit(str(settings.http_timeout_seconds))
        self.check_interval = QLineEdit(str(settings.check_interval_minutes))
        self.scheduler_hour = QLineEdit(settings.scheduler_hour)
        self.scheduler_minute = QLineEdit(settings.scheduler_minute)

        self.start_minimized = QCheckBox()
        self.start_minimized.setChecked(settings.start_minimized)

        self.minimize_to_tray = QCheckBox()
        self.minimize_to_tray.setChecked(settings.minimize_to_tray)

        self.sni_whitelist_url = QLineEdit(
            getattr(settings, "sni_whitelist_url", "")
        )

        self.download_sni_button = QPushButton("Скачать SNI whitelist")
        self.download_sni_button.clicked.connect(self.download_sni_whitelist)
        self.edit_sni_button = QPushButton("Изменить SNI whitelist")
        self.edit_sni_button.clicked.connect(self.open_sni_whitelist)
        self.edit_sni_pool_button = QPushButton("SNI из подписок")
        self.edit_sni_pool_button.clicked.connect(self.open_sni_domain_pool)

        self.ext_workers = QLineEdit(str(getattr(settings, "extended_rating_max_workers", 50)))
        self.ext_top_limit = QLineEdit(str(getattr(settings, "extended_rating_top_limit", 5000)))
        self.ext_timeout = QLineEdit(str(getattr(settings, "extended_rating_timeout_seconds", 10)))
        self.ext_retries = QLineEdit(str(getattr(settings, "extended_rating_retries", 3)))
        self.ext_submit_delay = QLineEdit(str(getattr(settings, "extended_rating_submit_delay_ms", 100)))
        self.ext_retry_delay = QLineEdit(str(getattr(settings, "extended_rating_retry_delay_ms", 1000)))

        form = QFormLayout()
        form.addRow("IP роутера", self.router_ip)
        form.addRow("HTTP белых списков", self.whitelist_check_urls)
        form.addRow("HTTP открытого интернета", self.open_internet_check_urls)
        form.addRow("HTTP timeout, секунд", self.http_timeout)
        form.addRow("Интервал проверки, минут", self.check_interval)
        form.addRow("Планировщик: час", self.scheduler_hour)
        form.addRow("Планировщик: минута", self.scheduler_minute)
        form.addRow("Стартовать свернутым", self.start_minimized)
        form.addRow("Сворачивать в трей", self.minimize_to_tray)
        form.addRow("URL списка SNI whitelist", self.sni_whitelist_url)

        sni_buttons = QHBoxLayout()
        sni_buttons.addWidget(self.download_sni_button)
        sni_buttons.addWidget(self.edit_sni_button)
        sni_buttons.addWidget(self.edit_sni_pool_button)
        sni_buttons.addStretch(1)
        form.addRow("", sni_buttons)

        form.addRow("e-рейтинг: максимум потоков", self.ext_workers)
        form.addRow("e-рейтинг: top серверов", self.ext_top_limit)
        form.addRow("e-рейтинг: TCP timeout, секунд", self.ext_timeout)
        form.addRow("e-рейтинг: попыток на сервер", self.ext_retries)
        form.addRow("e-рейтинг: пауза между стартами, мс", self.ext_submit_delay)
        form.addRow("e-рейтинг: пауза между попытками, мс", self.ext_retry_delay)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Вкл", "URL подписки", "Комментарий"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 760)
        self.table.setColumnWidth(2, 240)

        self.load_subscribes()

        add_btn = QPushButton("Добавить")
        del_btn = QPushButton("Удалить")
        import_btn = QPushButton("Импорт")
        export_btn = QPushButton("Экспорт")

        add_btn.clicked.connect(self.add_empty_row)
        del_btn.clicked.connect(self.delete_selected_rows)
        import_btn.clicked.connect(self.import_subscribes)
        export_btn.clicked.connect(self.export_subscribes)

        table_buttons = QHBoxLayout()
        table_buttons.addWidget(add_btn)
        table_buttons.addWidget(del_btn)
        table_buttons.addSpacing(20)
        table_buttons.addWidget(import_btn)
        table_buttons.addWidget(export_btn)
        table_buttons.addStretch(1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.table)
        layout.addLayout(table_buttons)
        layout.addWidget(buttons)

        self.ensure_sni_table()

    def ensure_sni_table(self) -> None:
        ensure_whitelist_sni_table(self.db)
        ensure_sni_domain_pool_table(self.db)

    def open_sni_whitelist(self) -> None:
        dialog = SniWhitelistDialog(self.db, self)
        dialog.exec()

    def open_sni_domain_pool(self) -> None:
        dialog = SniDomainPoolDialog(self.db, self)
        dialog.exec()

    def download_sni_whitelist(self) -> None:
        url = self.sni_whitelist_url.text().strip()

        if not url:
            QMessageBox.warning(
                self,
                "SNI whitelist",
                "Укажи URL списка SNI whitelist.",
            )
            return

        try:
            response = requests.get(
                url,
                timeout=25,
                headers={
                    "User-Agent": "WhiteListMonitor/0.1",
                    "Accept": "*/*",
                },
            )
            response.raise_for_status()
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Ошибка скачивания",
                f"Не удалось скачать SNI whitelist:\n{exc}",
            )
            return

        domains = self.extract_domains(response.text)

        if not domains:
            QMessageBox.information(
                self,
                "SNI whitelist",
                "В скачанном файле не найдено доменов.",
            )
            return

        added = 0
        duplicated = 0

        with self.db.connect() as con:
            for domain in domains:
                try:
                    con.execute(
                        """
                        INSERT INTO whitelist_sni (domain, enabled, comment)
                        VALUES (?, 1, '')
                        """,
                        (domain,),
                    )
                    added += 1
                except Exception:
                    duplicated += 1

        compacted = compact_sni_whitelist(self.db)
        QMessageBox.information(
            self,
            "SNI whitelist",
            f"Скачивание завершено.\n\n"
            f"Новых доменов добавлено: {added}\n"
            f"Уже были в базе: {duplicated}\n"
            f"Дубликатов после обрезки удалено: {compacted['removed']}",
        )

    def extract_domains(self, text: str) -> list[str]:
        result = []
        seen = set()

        for line in text.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith("#") or line.startswith("//") or line.startswith(";"):
                continue

            line = line.split("#", 1)[0].strip()
            line = line.split("//", 1)[0].strip()

            if not line:
                continue

            domain = self.normalize_domain_line(line)

            if not domain:
                continue

            if domain in seen:
                continue

            seen.add(domain)
            result.append(domain)

        return result

    def normalize_domain_line(self, line: str) -> str | None:
        return normalize_sni_domain(line)

    def load_subscribes(self) -> None:
        self.table.setRowCount(0)

        for sub in self.db.list_subscribes():
            self.add_row(sub)

    def add_empty_row(self) -> None:
        self.add_row(None)

    def add_row(self, sub: Subscribe | None = None) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        enabled_item = QTableWidgetItem()
        enabled_item.setFlags(
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsUserCheckable
        )
        enabled_item.setCheckState(
            Qt.CheckState.Checked
            if sub is None or sub.enabled
            else Qt.CheckState.Unchecked
        )
        enabled_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        url_item = QTableWidgetItem(sub.url if sub else "")
        url_item.setToolTip(sub.url if sub else "")

        comment_item = QTableWidgetItem(sub.comment if sub else "")

        self.table.setItem(row, 0, enabled_item)
        self.table.setItem(row, 1, url_item)
        self.table.setItem(row, 2, comment_item)

    def delete_selected_rows(self) -> None:
        rows = sorted(
            {index.row() for index in self.table.selectedIndexes()},
            reverse=True,
        )

        for row in rows:
            self.table.removeRow(row)

    def import_subscribes(self) -> None:
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Импорт подписок",
            str(Path.home()),
            "Списки подписок (*.csv *.txt);;CSV (*.csv);;Текст (*.txt);;Все файлы (*)",
        )

        if not file_name:
            return

        path = Path(file_name)

        try:
            if path.suffix.lower() == ".csv":
                imported = self.read_csv_subscribes(path)
            else:
                imported = self.read_txt_subscribes(path)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Ошибка импорта",
                f"Не удалось импортировать файл:\n{exc}",
            )
            return

        if not imported:
            QMessageBox.information(
                self,
                "Импорт подписок",
                "В файле не найдено подписок.",
            )
            return

        answer = QMessageBox.question(
            self,
            "Импорт подписок",
            "Заменить текущий список подписок импортированным?\n\n"
            "Да — заменить список.\n"
            "Нет — добавить к текущему списку.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if answer == QMessageBox.StandardButton.Yes:
            self.table.setRowCount(0)

        for sub in imported:
            self.add_row(sub)

        QMessageBox.information(
            self,
            "Импорт подписок",
            f"Импортировано: {len(imported)}",
        )

    def read_csv_subscribes(self, path: Path) -> list[Subscribe]:
        result = []

        with path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.reader(file)

            for row in reader:
                if not row:
                    continue

                row = [cell.strip() for cell in row]

                if not row[0] or row[0].lower() in {"enabled", "вкл"}:
                    continue

                enabled = True
                url = ""
                comment = ""

                if len(row) == 1:
                    url = row[0]

                elif len(row) == 2:
                    if self.looks_like_enabled(row[0]):
                        enabled = self.parse_enabled(row[0])
                        url = row[1]
                    else:
                        url = row[0]
                        comment = row[1]

                else:
                    enabled = self.parse_enabled(row[0])
                    url = row[1]
                    comment = row[2]

                if url:
                    result.append(
                        Subscribe(
                            id=None,
                            url=url,
                            enabled=enabled,
                            comment=comment,
                        )
                    )

        return result

    def read_txt_subscribes(self, path: Path) -> list[Subscribe]:
        result = []

        with path.open("r", encoding="utf-8-sig") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                result.append(
                    Subscribe(
                        id=None,
                        url=line,
                        enabled=True,
                        comment="",
                    )
                )

        return result

    def export_subscribes(self) -> None:
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт подписок",
            str(Path.home() / "wl_subscribes.csv"),
            "CSV (*.csv);;Текст (*.txt);;Все файлы (*)",
        )

        if not file_name:
            return

        path = Path(file_name)
        subscribes = self.collect_subscribes()

        try:
            if path.suffix.lower() == ".txt":
                self.write_txt_subscribes(path, subscribes)
            else:
                self.write_csv_subscribes(path, subscribes)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Ошибка экспорта",
                f"Не удалось экспортировать файл:\n{exc}",
            )
            return

        QMessageBox.information(
            self,
            "Экспорт подписок",
            f"Экспортировано: {len(subscribes)}",
        )

    def write_csv_subscribes(self, path: Path, subscribes: list[Subscribe]) -> None:
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["enabled", "url", "comment"])

            for sub in subscribes:
                writer.writerow(
                    [
                        1 if sub.enabled else 0,
                        sub.url,
                        sub.comment,
                    ]
                )

    def write_txt_subscribes(self, path: Path, subscribes: list[Subscribe]) -> None:
        with path.open("w", encoding="utf-8") as file:
            for sub in subscribes:
                file.write(sub.url + "\n")

    def looks_like_enabled(self, value: str) -> bool:
        return value.strip().lower() in {
            "1",
            "0",
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",
            "да",
            "нет",
            "вкл",
            "выкл",
        }

    def parse_enabled(self, value: str) -> bool:
        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
            "да",
            "вкл",
        }

    def format_url_list(self, urls: object, fallback: list[str]) -> str:
        if isinstance(urls, str):
            values = re.split(r"[\s,;]+", urls)
        elif isinstance(urls, (list, tuple, set)):
            values = [str(value) for value in urls]
        else:
            values = []

        normalized = [value.strip() for value in values if value.strip()]

        if not normalized:
            normalized = fallback

        return ", ".join(normalized)

    def parse_url_list(self, value: str, fallback: list[str]) -> list[str]:
        urls = []

        for part in re.split(r"[\s,;]+", value):
            url = part.strip()

            if not url:
                continue

            if "://" not in url:
                url = "http://" + url

            urls.append(url)

        if not urls:
            urls = fallback.copy()

        return list(dict.fromkeys(urls))

    def collect_settings(self) -> AppSettings:
        whitelist_check_urls = self.parse_url_list(
            self.whitelist_check_urls.text(),
            DEFAULT_WHITELIST_CHECK_URLS,
        )
        open_internet_check_urls = self.parse_url_list(
            self.open_internet_check_urls.text(),
            DEFAULT_OPEN_INTERNET_CHECK_URLS,
        )

        return AppSettings(
            router_ip=self.router_ip.text().strip() or "192.168.8.1",
            url_primary=whitelist_check_urls[0],
            url_secondary=open_internet_check_urls[0],
            whitelist_check_urls=whitelist_check_urls,
            open_internet_check_urls=open_internet_check_urls,
            http_timeout_seconds=max(
                1,
                self.safe_int(self.http_timeout.text(), 5),
            ),
            check_interval_minutes=max(
                1,
                self.safe_int(self.check_interval.text(), 5),
            ),
            scheduler_hour=self.scheduler_hour.text().strip() or "*",
            scheduler_minute=self.scheduler_minute.text().strip() or "15",
            start_minimized=self.start_minimized.isChecked(),
            minimize_to_tray=self.minimize_to_tray.isChecked(),
            sni_whitelist_url=self.sni_whitelist_url.text().strip(),
            extended_rating_max_workers=max(1, min(50, self.safe_int(self.ext_workers.text(), 50))),
            extended_rating_top_limit=max(1, self.safe_int(self.ext_top_limit.text(), 5000)),
            extended_rating_timeout_seconds=max(1, self.safe_int(self.ext_timeout.text(), 10)),
            extended_rating_retries=max(1, self.safe_int(self.ext_retries.text(), 3)),
            extended_rating_submit_delay_ms=max(0, self.safe_int(self.ext_submit_delay.text(), 100)),
            extended_rating_retry_delay_ms=max(0, self.safe_int(self.ext_retry_delay.text(), 1000)),
        )

    def collect_subscribes(self) -> list[Subscribe]:
        result = []

        for row in range(self.table.rowCount()):
            enabled_item = self.table.item(row, 0)
            url_item = self.table.item(row, 1)
            comment_item = self.table.item(row, 2)

            enabled = (
                enabled_item.checkState() == Qt.CheckState.Checked
                if enabled_item
                else True
            )

            url = url_item.text().strip() if url_item else ""
            comment = comment_item.text().strip() if comment_item else ""

            if url:
                result.append(
                    Subscribe(
                        id=None,
                        url=url,
                        enabled=enabled,
                        comment=comment,
                    )
                )

        return result

    def safe_int(self, value: str, default: int) -> int:
        try:
            return int(value.strip())
        except Exception:
            return default
