# Real-Time Network Monitor
# Copyright (c) 2025 Cypress Studios
# Licensed under the MIT License (see LICENSE file)

"""Real-Time Network Monitor by Cypress Studios.

A production-ready tool for monitoring network connections in real-time with a sleek,
Google-inspired UI. Features include connection filtering, CSV export, and task termination.
Requires PyQt5 and dnspython. Run with admin privileges for full functionality.
"""

import sys
import socket
import psutil
import threading
import logging
import os
import platform
import csv
import time
import dns.resolver
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QAbstractItemView, QTextEdit, QHeaderView, QStatusBar,
    QComboBox, QFileDialog, QLineEdit, QCheckBox, QMenu, QAction, QProgressBar, QMessageBox
)
from PyQt5.QtCore import QTimer, pyqtSignal, QObject, Qt, QCoreApplication, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor
from PyQt5.QtWidgets import QGraphicsDropShadowEffect
import queue

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f'realtime_network_monitor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

if platform.system() == 'Windows' and sys.stdout:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class NetworkSignals(QObject):
    update = pyqtSignal(list)
    log = pyqtSignal(str)
    error = pyqtSignal(str)
    scan_progress = pyqtSignal(bool)

class RealTimeNetworkMonitor(QWidget):
    def __init__(self, refresh_interval=5000, verbose_logging=False):
        super().__init__()
        self.setWindowTitle("Real-Time Network Monitor - Cypress Studios")
        self.resize(1200, 800)
        self.refresh_interval = refresh_interval
        self.verbose_logging = verbose_logging
        self.show_all_connections = False
        self.show_all_statuses = False
        self.entries_queue = queue.Queue()
        self.displayed_connections = set()
        self.is_scanning = False
        self.dns_cache = {}
        self.connection_details = {}
        self.process_filter = ""
        self.status_filter = ""
        self.proto_filter = ""
        self.last_scan_time = 0

        self.signals = NetworkSignals()
        self.signals.update.connect(self.safe_update_ui)
        self.signals.log.connect(self.safe_log)
        self.signals.error.connect(self.handle_error)
        self.signals.scan_progress.connect(self.update_scan_progress)

        self.setup_ui()
        self.start_queue_processor()
        self.check_permissions()

        self.timer = QTimer()
        self.timer.timeout.connect(self.fetch_and_update)
        self.timer.start(self.refresh_interval)

        self.fetch_and_update()

    def setup_ui(self):
        QApplication.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#F5F6F5"))
        palette.setColor(QPalette.WindowText, QColor("#212121"))
        QApplication.setPalette(palette)
        self.setStyleSheet("""
            QWidget { font-family: 'Roboto', Arial, sans-serif; font-size: 12pt; }
            QTableWidget {
                background-color: white;
                alternate-background-color: #E8ECEF;
                gridline-color: #B0BEC5;
                selection-background-color: #4DB6AC;
                font-size: 12pt;
                padding: 5px;
            }
            QTableWidget::item:hover { background-color: #80CBC4; color: white; }
            QHeaderView::section {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00695C, stop:1 #004D40);
                color: white;
                padding: 6px;
                border: none;
                font-weight: bold;
                font-size: 12pt;
            }
            QTextEdit {
                background-color: #ECEFF1;
                color: #212121;
                font-family: 'Courier New', monospace;
                font-size: 12pt;
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                padding: 5px;
            }
            QStatusBar {
                background-color: #E0E0E0;
                color: #212121;
                font-size: 12pt;
            }
            QLabel { font-size: 12pt; color: #212121; }
        """)

        layout = QVBoxLayout()

        header = QHBoxLayout()
        title_layout = QHBoxLayout()
        logo_label = QLabel("💻 Cypress Studios")
        logo_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #2E7D32; padding: 5px;")
        title = QLabel("Real-Time Network Monitor")
        title.setStyleSheet("""
            font-size: 18pt;
            font-weight: bold;
            color: #00695C;
            margin-left: 10px;
            padding: 5px;
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #E8ECEF, stop:1 #F5F6F5);
            border-radius: 6px;
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(2, 2)
        title.setGraphicsEffect(shadow)
        title_layout.addWidget(logo_label)
        title_layout.addWidget(title)
        header.addLayout(title_layout)
        header.addStretch()

        button_layout = QHBoxLayout()
        button_style = """
            QPushButton {
                background-color: %s;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 12pt;
                border: 1px solid %s;
            }
            QPushButton:hover { background-color: %s; }
            QPushButton:pressed { background-color: %s; }
        """

        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.setStyleSheet(button_style % ("#00695C", "#004D40", "#4DB6AC", "#004D40"))
        self.refresh_btn.setToolTip("Manually refresh network connections")
        self.refresh_btn.clicked.connect(self.fetch_and_update)
        self.add_button_animation(self.refresh_btn)
        button_layout.addWidget(self.refresh_btn)

        self.force_ui_btn = QPushButton("Force UI Update")
        self.force_ui_btn.setStyleSheet(button_style % ("#00796B", "#004D40", "#4DB6AC", "#004D40"))
        self.force_ui_btn.setToolTip("Force update the UI with queued data")
        self.force_ui_btn.clicked.connect(self.force_ui_update)
        self.add_button_animation(self.force_ui_btn)
        button_layout.addWidget(self.force_ui_btn)

        self.test_table_btn = QPushButton("Test Table")
        self.test_table_btn.setStyleSheet(button_style % ("#2E7D32", "#1B5E20", "#4CAF50", "#1B5E20"))
        self.test_table_btn.setToolTip("Insert a test row to verify UI")
        self.test_table_btn.clicked.connect(self.test_table)
        self.add_button_animation(self.test_table_btn)
        button_layout.addWidget(self.test_table_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(button_style % ("#D32F2F", "#B71C1C", "#EF5350", "#B71C1C"))
        self.clear_btn.setToolTip("Clear the table")
        self.clear_btn.clicked.connect(self.clear_data)
        self.add_button_animation(self.clear_btn)
        button_layout.addWidget(self.clear_btn)

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.setStyleSheet(button_style % ("#FBC02D", "#F57F17", "#FFD54F", "#F57F17"))
        self.copy_btn.setToolTip("Copy table data to clipboard")
        self.copy_btn.clicked.connect(self.copy_data)
        self.add_button_animation(self.copy_btn)
        button_layout.addWidget(self.copy_btn)

        self.export_btn = QPushButton("Export to CSV")
        self.export_btn.setStyleSheet(button_style % ("#8E24AA", "#6A1B9A", "#AB47BC", "#6A1B9A"))
        self.export_btn.setToolTip("Export table data to CSV")
        self.export_btn.clicked.connect(self.export_to_csv)
        self.add_button_animation(self.export_btn)
        button_layout.addWidget(self.export_btn)

        self.verbose_btn = QPushButton("Toggle Verbose Logging")
        self.verbose_btn.setStyleSheet(button_style % ("#455A64", "#263238", "#607D8B", "#263238"))
        self.verbose_btn.setToolTip("Toggle detailed logging")
        self.verbose_btn.clicked.connect(self.toggle_verbose)
        self.add_button_animation(self.verbose_btn)
        button_layout.addWidget(self.verbose_btn)

        self.all_conns_btn = QPushButton("Toggle All Connections")
        self.all_conns_btn.setStyleSheet(button_style % ("#0097A7", "#006064", "#4DD0E1", "#006064"))
        self.all_conns_btn.setToolTip("Show/hide non-TCP/UDP connections")
        self.all_conns_btn.clicked.connect(self.toggle_all_connections)
        self.add_button_animation(self.all_conns_btn)
        button_layout.addWidget(self.all_conns_btn)

        self.all_statuses_btn = QPushButton("Toggle All Statuses")
        self.all_statuses_btn.setStyleSheet(button_style % ("#00838F", "#005662", "#4DB6AC", "#005662"))
        self.all_statuses_btn.setToolTip("Show/hide TIME_WAIT connections")
        self.all_statuses_btn.clicked.connect(self.toggle_all_statuses)
        self.add_button_animation(self.all_statuses_btn)
        button_layout.addWidget(self.all_statuses_btn)

        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter by Process:")
        filter_layout.addWidget(filter_label)
        self.process_filter_input = QLineEdit()
        self.process_filter_input.setPlaceholderText("Enter process name (e.g., firefox.exe)")
        self.process_filter_input.setStyleSheet("""
            QLineEdit {
                padding: 6px;
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                font-size: 12pt;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #00695C;
                background-color: #F5F6F5;
            }
        """)
        self.process_filter_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.process_filter_input)

        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItems(["All Statuses", "ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "NONE"])
        self.status_filter_combo.setStyleSheet("""
            QComboBox {
                padding: 6px;
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                font-size: 12pt;
                background-color: white;
            }
            QComboBox:hover { border-color: #00695C; }
        """)
        self.status_filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(QLabel("Status:", styleSheet="font-size: 12pt; color: #212121;"))
        filter_layout.addWidget(self.status_filter_combo)

        self.proto_filter_combo = QComboBox()
        self.proto_filter_combo.addItems(["All Protocols", "TCP", "UDP", "OTHER"])
        self.proto_filter_combo.setStyleSheet("""
            QComboBox {
                padding: 6px;
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                font-size: 12pt;
                background-color: white;
            }
            QComboBox:hover { border-color: #00695C; }
        """)
        self.proto_filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(QLabel("Protocol:", styleSheet="font-size: 12pt; color: #212121;"))
        filter_layout.addWidget(self.proto_filter_combo)

        self.auto_refresh_check = QCheckBox("Auto Refresh")
        self.auto_refresh_check.setChecked(True)
        self.auto_refresh_check.setStyleSheet("font-size: 12pt; color: #212121;")
        self.auto_refresh_check.stateChanged.connect(self.toggle_auto_refresh)
        filter_layout.addWidget(self.auto_refresh_check)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                text-align: center;
                background-color: #ECEFF1;
                font-size: 12pt;
                color: #212121;
            }
            QProgressBar::chunk { background-color: #00695C; }
        """)
        filter_layout.addWidget(self.progress_bar)

        layout.addLayout(header)
        layout.addLayout(button_layout)
        layout.addLayout(filter_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "PID", "User", "Process", "Proto", "Local Address", "Remote Address",
            "Remote Host", "Status", "Socket Type"
        ])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.setToolTip("Right-click for connection details or to kill task")
        layout.addWidget(self.table)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(200)
        self.log.setStyleSheet("""
            QTextEdit {
                background-color: #ECEFF1;
                color: #212121;
                font-family: 'Courier New', monospace;
                font-size: 12pt;
                border: 1px solid #B0BEC5;
                border-radius: 6px;
                padding: 5px;
            }
        """)
        layout.addWidget(QLabel("Log:", styleSheet="font-size: 12pt; color: #212121;"))
        layout.addWidget(self.log)

        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("font-size: 12pt; color: #212121; background-color: #E0E0E0;")
        self.status_bar.showMessage("Ready")
        layout.addWidget(self.status_bar)

        self.setLayout(layout)
        self.setWindowIcon(QIcon.fromTheme("network"))

    def add_button_animation(self, button):
        animation = QPropertyAnimation(button, b"geometry")
        animation.setDuration(100)
        original_geometry = button.geometry()
        animation.setStartValue(original_geometry)
        animation.setEndValue(original_geometry.adjusted(0, 0, -2, -2))
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        button.clicked.connect(lambda: animation.start())
        animation.finished.connect(lambda: button.setGeometry(original_geometry))

    def start_queue_processor(self):
        def process_queue():
            while True:
                try:
                    entries = self.entries_queue.get(block=True, timeout=0.2)
                    logger.debug(f"Queue processor got {len(entries)} entries")
                    self.signals.update.emit(entries)
                    self.entries_queue.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    self.signals.error.emit(f"Queue processor error: {e}")
                    logger.error(f"Queue processor error: {e}")

        threading.Thread(target=process_queue, daemon=True, name="QueueProcessor").start()

    def check_permissions(self):
        if platform.system() in ['Linux', 'Darwin'] and os.geteuid() != 0:
            self.log_message("Warning: Run with sudo for full network data access.")
        elif platform.system() == 'Windows' and not self.is_admin():
            self.log_message("Warning: Run as Administrator for full network data access.")
        else:
            self.log_message("Running with full permissions. No limits.")

    def is_admin(self):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def log_message(self, msg):
        self.signals.log.emit(msg)

    def safe_log(self, msg):
        try:
            if "error" in msg.lower():
                self.log.append(f'<span style="color: #D32F2F;">{msg}</span>')
            else:
                self.log.append(msg)
            if self.verbose_logging:
                logger.debug(msg)
            else:
                logger.info(msg)
        except Exception as e:
            logger.error(f"Error logging message: {e}")

    def handle_error(self, msg):
        self.log_message(msg)
        self.status_bar.showMessage("Error occurred, check log.")

    def update_scan_progress(self, is_scanning):
        self.progress_bar.setVisible(is_scanning)
        if is_scanning:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)

    def toggle_verbose(self):
        self.verbose_logging = not self.verbose_logging
        logger.setLevel(logging.DEBUG if self.verbose_logging else logging.INFO)
        self.log_message(f"Verbose logging {'enabled' if self.verbose_logging else 'disabled'}")

    def toggle_all_connections(self):
        self.show_all_connections = not self.show_all_connections
        self.log_message(f"Show all connections {'enabled' if self.show_all_connections else 'disabled'}")
        self.displayed_connections.clear()
        self.fetch_and_update()

    def toggle_all_statuses(self):
        self.show_all_statuses = not self.show_all_statuses
        self.log_message(f"Show all statuses {'enabled' if self.show_all_statuses else 'disabled'}")
        self.displayed_connections.clear()
        self.fetch_and_update()

    def toggle_auto_refresh(self):
        if self.auto_refresh_check.isChecked():
            self.timer.start(self.refresh_interval)
            self.log_message("Auto-refresh enabled.")
        else:
            self.timer.stop()
            self.log_message("Auto-refresh disabled.")

    def clear_data(self):
        self.table.setRowCount(0)
        self.displayed_connections.clear()
        self.connection_details.clear()
        self.log_message("Cleared table data.")
        self.status_bar.showMessage("Table cleared.")

    def copy_data(self):
        rows = self.table.rowCount()
        cols = self.table.columnCount()
        headers = [self.table.horizontalHeaderItem(i).text() for i in range(cols)]
        data = ["\t".join(headers)]
        for r in range(rows):
            if not self.table.isRowHidden(r):
                row = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(cols)]
                data.append("\t".join(row))
        QApplication.clipboard().setText("\n".join(data))
        self.log_message(f"Copied {rows} rows to clipboard.")
        self.status_bar.showMessage(f"Copied {rows} rows.")

    def export_to_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if not file_path:
            return

        rows = self.table.rowCount()
        cols = self.table.columnCount()
        headers = [self.table.horizontalHeaderItem(i).text() for i in range(cols)]
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in range(rows):
                if not self.table.isRowHidden(r):
                    row = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(cols)]
                    writer.writerow(row)
        
        self.log_message(f"Exported {rows} rows to {file_path}")
        self.status_bar.showMessage(f"Exported to {file_path}")

    def apply_filter(self):
        self.process_filter = self.process_filter_input.text().lower()
        self.status_filter = self.status_filter_combo.currentText()
        self.proto_filter = self.proto_filter_combo.currentText()
        if self.status_filter == "All Statuses":
            self.status_filter = ""
        if self.proto_filter == "All Protocols":
            self.proto_filter = ""

        for row in range(self.table.rowCount()):
            process = self.table.item(row, 2).text().lower() if self.table.item(row, 2) else ""
            status = self.table.item(row, 7).text() if self.table.item(row, 7) else ""
            proto = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
            match_process = not self.process_filter or self.process_filter in process
            match_status = not self.status_filter or status == self.status_filter
            match_proto = not self.proto_filter or proto == self.proto_filter
            self.table.setRowHidden(row, not (match_process and match_status and match_proto))
            if not self.table.isRowHidden(row):
                key = f"{self.table.item(row, 0).text()}:{self.table.item(row, 4).text()}:{self.table.item(row, 5).text()}:{self.table.item(row, 7).text()}"
                tooltip = self.connection_details.get(key, "No details available.")
                self.table.item(row, 0).setToolTip(tooltip)
        
        self.log_message(f"Applied filter: process='{self.process_filter}', status='{self.status_filter}', proto='{self.proto_filter}'")

    def show_context_menu(self, pos):
        menu = QMenu()
        details_action = QAction("Show Connection Details", self)
        details_action.triggered.connect(self.show_connection_details)
        menu.addAction(details_action)
        kill_action = QAction("Kill Task", self)
        kill_action.triggered.connect(self.kill_task)
        menu.addAction(kill_action)
        menu.exec_(self.table.mapToGlobal(pos))

    def show_connection_details(self):
        selected_rows = [index.row() for index in self.table.selectionModel().selectedRows()]
        if not selected_rows:
            self.log_message("No row selected for details.")
            return

        row = selected_rows[0]
        key = f"{self.table.item(row, 0).text()}:{self.table.item(row, 4).text()}:{self.table.item(row, 5).text()}:{self.table.item(row, 7).text()}"
        details = self.connection_details.get(key, "No additional details available.")
        self.log_message(f"Connection details for {key}: {details}")
        self.status_bar.showMessage("Details shown in log.")

    def kill_task(self):
        selected_rows = [index.row() for index in self.table.selectionModel().selectedRows()]
        if not selected_rows:
            self.log_message("No row selected to kill task.")
            return

        row = selected_rows[0]
        pid = self.table.item(row, 0).text()
        process_name = self.table.item(row, 2).text()

        reply = QMessageBox.question(
            self, "Confirm Kill Task",
            f"Are you sure you want to terminate process {process_name} (PID: {pid})?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                if pid != "0":
                    process = psutil.Process(int(pid))
                    process.terminate()
                    self.log_message(f"Terminated process {process_name} (PID: {pid})")
                    self.status_bar.showMessage(f"Terminated process {process_name}")
                    self.fetch_and_update()
                else:
                    self.log_message("Cannot terminate system process (PID: 0)")
                    self.status_bar.showMessage("Cannot terminate system process")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.log_message(f"Failed to terminate process {process_name} (PID: {pid}): {e}")
                self.status_bar.showMessage("Failed to terminate process")

    def test_table(self):
        self.table.setRowCount(0)
        self.table.setRowCount(1)
        test_row = ["TEST", "TEST", "TEST", "TEST", "TEST", "TEST", "TEST", "TEST", "1"]
        for col, value in enumerate(test_row):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(0, col, item)
        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)
        self.log_message("Test row inserted into table.")
        logger.info("Test row inserted into table.")
        self.status_bar.showMessage("Test row inserted.")

    def force_ui_update(self):
        self.log_message("Forcing UI update...")
        logger.info("Forcing UI update")
        try:
            entries = self.entries_queue.get_nowait()
            logger.debug(f"Forcing UI update with {len(entries)} entries")
            QCoreApplication.processEvents()
            self.signals.update.emit(entries)
            self.entries_queue.task_done()
        except queue.Empty:
            self.log_message("No entries available for UI update.")
            logger.info("No entries available for UI update.")
            self.status_bar.showMessage("No entries available.")

    def safe_update_ui(self, entries):
        logger.debug(f"Entering safe_update_ui with {len(entries)} entries")
        new_entries = []
        for entry in entries:
            key = f"{entry[0]}:{entry[4]}:{entry[5]}:{entry[7]}"
            if key not in self.displayed_connections:
                new_entries.append(entry)
                self.displayed_connections.add(key)
                self.connection_details[key] = f"Added at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        if not new_entries:
            self.log_message("No new connections to display.")
            logger.info("No new connections to display.")
            self.status_bar.showMessage("No new connections.")
            return

        logger.debug(f"Adding {len(new_entries)} new entries to table")
        current_rows = self.table.rowCount()
        self.table.setRowCount(current_rows + len(new_entries))

        for row_index, row_data in enumerate(new_entries, current_rows):
            for col_index, value in enumerate(row_data):
                item = QTableWidgetItem(str(value) if value is not None else "")
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                self.table.setItem(row_index, col_index, item)
                if self.verbose_logging:
                    logger.debug(f"Set table item: row={row_index}, col={col_index}, value={value}")

        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)
        self.apply_filter()
        self.log_message(f"UI update complete. {len(new_entries)} new rows added, total {self.table.rowCount()} rows.")
        logger.info(f"UI update complete. {len(new_entries)} new rows added, total {self.table.rowCount()} rows.")
        self.status_bar.showMessage(f"Displayed {self.table.rowCount()} active sockets.")
        logger.debug(f"Table row count after update: {self.table.rowCount()}")

    def fetch_and_update(self):
        if self.is_scanning:
            self.log_message("Scan already in progress, skipping...")
            logger.info("Scan already in progress, skipping...")
            return

        def worker():
            try:
                self.is_scanning = True
                self.signals.scan_progress.emit(True)
                new_entries = []
                self.log_message("Scanning all active sockets...")
                logger.info("Scanning all active sockets...")
                self.status_bar.showMessage("Scanning...")
                start_time = time.time()

                timeout = 3.0
                try:
                    conns = psutil.net_connections(kind='all')
                    logger.debug(f"Retrieved {len(conns)} connections from psutil in {time.time() - start_time:.2f}s")
                except Exception as e:
                    self.log_message(f"psutil error: {e}")
                    logger.error(f"psutil error: {e}")
                    self.signals.scan_progress.emit(False)
                    return

                if time.time() - start_time > timeout:
                    self.log_message("Scan timed out.")
                    logger.error("Scan timed out.")
                    self.signals.scan_progress.emit(False)
                    return

                for conn in conns:
                    try:
                        pid = conn.pid if conn.pid is not None else 0
                        name = 'Unknown'
                        user = 'Unknown'

                        if pid > 0:
                            try:
                                proc = psutil.Process(pid)
                                name = proc.name()
                                user = proc.username()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                if self.verbose_logging:
                                    logger.debug(f"Could not get info for PID {pid}")
                                pass

                        if not self.show_all_connections and conn.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                            if self.verbose_logging:
                                logger.debug(f"Skipping non-TCP/UDP connection for PID {pid}: type={conn.type}")
                            continue
                        if not self.show_all_statuses and conn.status == 'TIME_WAIT':
                            if self.verbose_logging:
                                logger.debug(f"Skipping TIME_WAIT connection for PID {pid}: laddr={conn.laddr}, raddr={conn.raddr}")
                            continue

                        proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'OTHER'
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '-'
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '-'
                        status = conn.status or '-'
                        socktype = str(conn.type)

                        host = "N/A"
                        if conn.raddr and conn.raddr.ip:
                            ip = conn.raddr.ip
                            if ip in self.dns_cache:
                                host = self.dns_cache[ip]
                            else:
                                try:
                                    resolver = dns.resolver.Resolver()
                                    resolver.timeout = 0.3
                                    resolver.lifetime = 0.3
                                    answers = resolver.resolve_address(ip)
                                    host = answers[0].to_text()
                                    self.dns_cache[ip] = host
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                                    host = ip
                                except Exception as e:
                                    host = "Error"
                                    if self.verbose_logging:
                                        logger.debug(f"Error resolving host for {raddr}: {e}")

                        if self.verbose_logging:
                            logger.debug(f"Adding connection for PID {pid}: {proto} {laddr} -> {raddr} ({status})")
                        new_entries.append((pid, user, name, proto, laddr, raddr, host, status, socktype))
                    except Exception as e:
                        self.log_message(f"Error processing connection: {e}")
                        logger.error(f"Error processing connection: {e}")
                        continue

                self.entries_queue.put(new_entries)
                logger.debug(f"Worker found {len(new_entries)} connections in {time.time() - start_time:.2f}s")
                self.log_message(f"Scan complete. {len(new_entries)} total sockets.")
                logger.info(f"Scan complete. {len(new_entries)} total sockets.")
                self.status_bar.showMessage("Scan complete.")
                self.last_scan_time = time.time()
                self.signals.scan_progress.emit(False)

                QCoreApplication.processEvents()

            except Exception as e:
                self.log_message(f"Worker error: {e}")
                logger.error(f"Worker error: {e}")
                self.status_bar.showMessage("Worker failed.")
                self.signals.scan_progress.emit(False)
            finally:
                self.is_scanning = False

        threading.Thread(target=worker, daemon=True, name="WorkerThread").start()

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        app.setFont(QFont("Roboto", 12))
        win = RealTimeNetworkMonitor(refresh_interval=5000, verbose_logging=False)
        win.show()
        QCoreApplication.processEvents()
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f"Application failed to start: {e}")
        raise