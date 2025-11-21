import sys
import os
import subprocess
import time
from pydbus import SessionBus
from gi.repository import GLib
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout,
                             QPushButton, QLabel, QListWidget,
                             QSystemTrayIcon, QMenu)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon, QAction
from pynput import keyboard

# ==========================================
# 1. THE HOTKEY WORKER (Thread)
# ==========================================
class HotkeyWorker(QObject):
    request_toggle = pyqtSignal()

    def start_listening(self):
        # Global Hotkey: Ctrl + Shift + Z
        try:
            self.listener = keyboard.GlobalHotKeys({
                '<ctrl>+<shift>+z': self.on_activate
            })
            self.listener.start()
        except Exception as e:
            print(f"Hotkey Error: {e}")

    def on_activate(self):
        self.request_toggle.emit()

# ==========================================
# 2. THE CORE LOGIC (Systemd + Audio)
# ==========================================
class StasisCore:
    def __init__(self):
        try:
            self.bus = SessionBus()
            self.systemd = self.bus.get(".systemd1", "/org/freedesktop/systemd1")
            self.manager = self.systemd["org.freedesktop.systemd1.Manager"]
        except Exception as e:
            print(f"DBus Error: {e}")
        self.frozen_apps = {}

    def get_active_window_info(self):
        try:
            # Only tracking PID and Name
            wid = subprocess.check_output(["xdotool", "getactivewindow"], text=True).strip()
            pid = int(subprocess.check_output(["xdotool", "getwindowpid", wid], text=True).strip())
            name = subprocess.check_output(["xdotool", "getwindowname", wid], text=True).strip()
            return {"pid": pid, "name": name}
        except:
            return None

    def get_audio_id(self, pid):
        try:
            full_output = subprocess.check_output(["pactl", "list", "sink-inputs"], text=True)
            current_id = None
            for line in full_output.split('\n'):
                line = line.strip()
                if line.startswith("Sink Input #"):
                    current_id = line.split("#")[1]
                if f"application.process.id = \"{pid}\"" in line:
                    return current_id
            return None
        except:
            return None

    def freeze(self, app_info):
        pid = app_info['pid']
        if pid in self.frozen_apps: return

        print(f"Freezing PID {pid}...")

        # 1. Mute Audio
        aud_id = self.get_audio_id(pid)
        if aud_id: subprocess.run(["pactl", "set-sink-input-mute", aud_id, "1"])

        # 2. Create Scope
        scope_name = f"stasis-{pid}.scope"
        try:
            pids_variant = GLib.Variant("au", [pid])
            self.manager.StartTransientUnit(scope_name, "fail", [("PIDs", pids_variant)], [])
        except: pass

        # 3. Freeze Scope
        subprocess.run(["systemctl", "--user", "freeze", scope_name])

        self.frozen_apps[pid] = {"scope": scope_name, "audio": aud_id, "name": app_info['name']}

    def thaw(self, pid):
        if pid not in self.frozen_apps: return
        data = self.frozen_apps[pid]

        print(f"Thawing PID {pid}...")

        # 1. Thaw Scope
        subprocess.run(["systemctl", "--user", "thaw", data['scope']])

        # 2. Unmute Audio
        if data['audio']: subprocess.run(["pactl", "set-sink-input-mute", data['audio'], "0"])

        del self.frozen_apps[pid]

# ==========================================
# 3. THE HUD & TRAY
# ==========================================
class StasisHUD(QWidget):
    def __init__(self):
        super().__init__()
        self.core = StasisCore()

        # Resolve icon path (looks for logo.png in same dir)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.icon_path = os.path.join(script_dir, "logo.png")

        # Hotkey Thread
        self.hotkey_thread = QThread()
        self.hotkey_worker = HotkeyWorker()
        self.hotkey_worker.moveToThread(self.hotkey_thread)
        self.hotkey_worker.request_toggle.connect(self.handle_hotkey)
        self.hotkey_thread.started.connect(self.hotkey_worker.start_listening)
        self.hotkey_thread.start()

        self.init_ui()
        self.init_tray()

    def init_ui(self):
        self.setWindowTitle("Ion Trap HUD")
        self.setGeometry(50, 50, 300, 350)
        self.setWindowIcon(QIcon(self.icon_path))

        # Dark Theme
        p = self.palette()
        p.setColor(QPalette.ColorRole.Window, QColor(30, 30, 35))
        p.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        self.setPalette(p)

        layout = QVBoxLayout()

        header = QLabel("ION TRAP")
        header.setFont(QFont("Impact", 24))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #3daee9;")
        layout.addWidget(header)

        sub = QLabel("Ctrl + Shift + Z")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color: gray; margin-bottom: 10px;")
        layout.addWidget(sub)

        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet("background-color: #252528; border: none; color: white;")
        layout.addWidget(self.list_widget)

        self.setLayout(layout)

    def init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(self.icon_path))
        self.tray_icon.setToolTip("Ion Trap (Running)")

        # Tray Menu
        menu = QMenu()

        show_action = QAction("Open HUD", self)
        show_action.triggered.connect(self.show_window)
        menu.addAction(show_action)

        quit_action = QAction("Quit Ion Trap", self)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.on_tray_click)
        self.tray_icon.show()

    def on_tray_click(self, reason):
        # Left click toggles window
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show_window()

    def show_window(self):
        self.show()
        self.activateWindow()

    def quit_app(self):
        # Thaw everything before quitting to prevent lost processes
        pids = list(self.core.frozen_apps.keys())
        for pid in pids:
            self.core.thaw(pid)
        QApplication.quit()

    def closeEvent(self, event):
        # Override close button to minimize to tray
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Ion Trap Active",
            "Process containment field ready. Ctrl+Shift+Z to engage.",
            QSystemTrayIcon.MessageIcon.Information,
            2000
        )

    def handle_hotkey(self):
        info = self.core.get_active_window_info()
        if not info: return

        pid = info['pid']
        if pid == os.getpid(): return

        if pid in self.core.frozen_apps:
            self.core.thaw(pid)
            self.tray_icon.showMessage("Ion Trap", f"Released: {info['name']}", QSystemTrayIcon.MessageIcon.Information, 1000)
        else:
            self.core.freeze(info)
            self.tray_icon.showMessage("Ion Trap", f"Captured: {info['name']}", QSystemTrayIcon.MessageIcon.Warning, 1000)

        self.update_list()

    def update_list(self):
        self.list_widget.clear()
        for pid, data in self.core.frozen_apps.items():
            self.list_widget.addItem(f"{data['name']} (PID: {pid})")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False) # Essential for tray apps!
    app.setStyle("Fusion")

    window = StasisHUD()
    # Start minimized (uncomment next line to show on start)
    # window.show()

    sys.exit(app.exec())
