import sys
import os
import stat
import paramiko
import io
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import urllib.request

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit, QLineEdit,
    QDialog, QFormLayout, QPushButton, QDialogButtonBox,
    QMessageBox, QStyle, QMenu, QFileDialog, QProgressDialog,
    QListWidget, QListWidgetItem, QInputDialog
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSlot, pyqtSignal, QTimer
from mobatuxtermfiles.ssh_worker import SshWorker

APP_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(APP_ROOT_DIR)

class ConnectionDialog(QDialog):
    """
    A dialog box to get SSH connection details from the user.
    Now includes a session name.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Connection Details")
        self.setModal(True)

        self.layout = QFormLayout(self)

        self.name_input = QLineEdit("My Server")
        self.host_input = QLineEdit("127.0.0.1")
        self.port_input = QLineEdit("22")
        self.user_input = QLineEdit("username")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.layout.addRow("Session Name:", self.name_input)
        self.layout.addRow("Host:", self.host_input)
        self.layout.addRow("Port:", self.port_input)
        self.layout.addRow("Username:", self.user_input)
        self.layout.addRow("Password:", self.pass_input)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def get_details(self):
        """Returns the connection details as a dictionary."""
        return {
            "name": self.name_input.text(),
            "host": self.host_input.text(),
            "port": int(self.port_input.text()),
            "user": self.user_input.text(),
            "password": self.pass_input.text()
        }

class RemoteTextEditorDialog(QDialog):
    """
    A dialog to edit a remote text file.
    It no longer knows about SFTP. It just emits a signal on save.
    """
    # Signal to emit when user clicks "Save"
    save_requested = pyqtSignal(str, str) # remote_path, new_content

    def __init__(self, remote_path, file_content, parent=None):
        super().__init__(parent)
        self.remote_path = remote_path

        self.setWindowTitle(f"Editing: {remote_path}")
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout(self)

        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Monospace", 10))
        layout.addWidget(self.text_edit)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        layout.addWidget(self.buttons)

        # Now that self.text_edit exists, we can set its text
        self.text_edit.setText(file_content)

        # Now that self.buttons exists, we can connect its signals
        self.buttons.accepted.connect(self.request_save)
        self.buttons.rejected.connect(self.reject)

    def request_save(self):
        """
        Emits the new content and accepts the dialog.
        The MainWindow will handle the actual saving.
        """
        content = self.text_edit.toPlainText()
        self.save_requested.emit(self.remote_path, content)
        self.accept()

class SessionManagerDialog(QDialog):
    """
    Manages loading, creating, and deleting sessions.
    Also handles the master password.
    """
    # Define the directory
    CONFIG_DIR = "mobatuxtermfiles"
    SESSIONS_FILE = os.path.join(APP_ROOT_DIR, "mobatuxtermfiles", "mobatuxterm_sessions.json")

    def __init__(self, parent=None):
        # Get the full, absolute path to the directory for the session file
        session_dir = os.path.dirname(self.SESSIONS_FILE)
        os.makedirs(session_dir, exist_ok=True)
        super().__init__(parent)
        self.setWindowTitle("MobaTuxTerm Session Manager")
        self.setMinimumWidth(400)

        self.master_key = None
        self.salt = None
        self.sessions = []
        self.selected_session_details = None

        self.layout = QVBoxLayout(self)

        # Master Password
        self.pass_layout = QFormLayout()
        self.master_pass_input = QLineEdit()
        self.master_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_layout.addRow("Master Password:", self.master_pass_input)
        self.layout.addLayout(self.pass_layout)

        self.unlock_button = QPushButton("Unlock / Initialize")
        self.unlock_button.clicked.connect(self.unlock_sessions)
        self.layout.addWidget(self.unlock_button)

        # Session List (initially hidden)
        self.session_list_widget = QListWidget()
        self.session_list_widget.itemDoubleClicked.connect(self.connect_session)
        self.layout.addWidget(self.session_list_widget)

        # Buttons (initially hidden)
        self.button_layout = QHBoxLayout()
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_session)
        self.new_button = QPushButton("New...")
        self.new_button.clicked.connect(self.new_session)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_session)

        self.button_layout.addWidget(self.connect_button)
        self.button_layout.addWidget(self.new_button)
        self.button_layout.addWidget(self.delete_button)
        self.layout.addLayout(self.button_layout)

        # Hide session UI until unlocked
        self.session_list_widget.hide()
        self.connect_button.hide()
        self.new_button.hide()
        self.delete_button.hide()

    def get_key_from_password(self, password, salt):
        """Derives a 32-byte key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def unlock_sessions(self):
        """Attempts to load and decrypt sessions with the given master password."""
        password = self.master_pass_input.text()
        if not password:
            QMessageBox.warning(self, "Password", "Please enter a master password.")
            return

        try:
            if os.path.exists(self.SESSIONS_FILE):
                # File exists, try to decrypt
                with open(self.SESSIONS_FILE, 'r') as f:
                    data = json.load(f)
                self.salt = base64.urlsafe_b64decode(data['salt'])
                self.master_key = self.get_key_from_password(password, self.salt)
                fernet = Fernet(base64.urlsafe_b64encode(self.master_key))

                self.sessions = []
                for s in data['sessions']:
                    s_decrypted = s.copy()
                    s_decrypted['password'] = fernet.decrypt(s['encrypted_password'].encode()).decode()
                    self.sessions.append(s_decrypted)

            else:
                # First time run: create new salt and use this password
                self.salt = os.urandom(16)
                self.master_key = self.get_key_from_password(password, self.salt)
                self.sessions = []
                self.save_sessions() # Save the empty file with salt
                QMessageBox.information(self, "Welcome", "Master password set. You can now create new sessions.")

            # Success! Show session UI
            self.master_pass_input.setDisabled(True)
            self.unlock_button.setDisabled(True)

            self.session_list_widget.show()
            self.connect_button.show()
            self.new_button.show()
            self.delete_button.show()

            self.populate_session_list()

        except Exception as e:
            self.master_key = None # Reset key on failure
            QMessageBox.critical(self, "Unlock Failed", f"Incorrect password or corrupted session file.\n{e}")

    def populate_session_list(self):
        self.session_list_widget.clear()
        for session in self.sessions:
            item = QListWidgetItem(f"{session['name']} ({session['user']}@{session['host']})")
            item.setData(Qt.ItemDataRole.UserRole, session)
            self.session_list_widget.addItem(item)

    def save_sessions(self):
        """Encrypts and saves all current sessions to file."""
        if not self.master_key or not self.salt:
            QMessageBox.critical(self, "Error", "Cannot save sessions without a master key.")
            return

        fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_sessions = []
        for s in self.sessions:
            encrypted_s = s.copy()
            encrypted_s['encrypted_password'] = fernet.encrypt(s['password'].encode()).decode()
            del encrypted_s['password'] # Don't save plaintext password
            encrypted_sessions.append(encrypted_s)

        data = {
            'salt': base64.urlsafe_b64encode(self.salt).decode(),
            'sessions': encrypted_sessions
        }

        try:
            with open(self.SESSIONS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not write session file:\n{e}")

    def connect_session(self):
        """Sets the selected session and accepts the dialog."""
        selected_item = self.session_list_widget.currentItem()
        if not selected_item:
            return

        self.selected_session_details = selected_item.data(Qt.ItemDataRole.UserRole)
        self.accept()

    def new_session(self):
        """Shows the ConnectionDialog to create a new session."""
        conn_dialog = ConnectionDialog(self)
        if conn_dialog.exec() == QDialog.DialogCode.Accepted:
            new_session_details = conn_dialog.get_details()
            # Check for duplicate names
            if any(s['name'] == new_session_details['name'] for s in self.sessions):
                QMessageBox.warning(self, "Duplicate Name", "A session with this name already exists.")
                return

            self.sessions.append(new_session_details)
            self.save_sessions()
            self.populate_session_list()

    def delete_session(self):
        """Deletes the selected session."""
        selected_item = self.session_list_widget.currentItem()
        if not selected_item:
            return

        session_data = selected_item.data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete session '{session_data['name']}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.sessions = [s for s in self.sessions if s['name'] != session_data['name']]
            self.save_sessions()
            self.populate_session_list()

    def get_selected_session(self):
        return self.selected_session_details

class UpdateChecker(QThread):
    """
    Checks a raw text file on GitHub for version number.
    """
    update_available = pyqtSignal(str) # Signal emits the new version number

    VERSION_URL = "https://raw.githubusercontent.com/ION-FX/ionos/main/apps/mobatuxterm/mobatuxtermfiles/version.txt"
    LOCAL_VERSION_FILE = os.path.join(APP_ROOT_DIR, "mobatuxtermfiles", "version.txt")

    def run(self):
        try:
            # 1. Get remote version
            with urllib.request.urlopen(self.VERSION_URL, timeout=5) as response:
                remote_ver_str = response.read().decode('utf-8').strip()
                remote_ver = int(remote_ver_str)

            # 2. Get local version
            if os.path.exists(self.LOCAL_VERSION_FILE):
                with open(self.LOCAL_VERSION_FILE, 'r') as f:
                    local_ver_str = f.read().strip()
                    local_ver = int(local_ver_str)
            else:
                # If local file is missing, assume version 0
                local_ver = 0

            # 3. Compare
            if remote_ver > local_ver:
                self.update_available.emit(remote_ver_str)

        except Exception as e:
            print(f"Update check failed: {e}")

class AppUpdater(QThread):
    """
    Downloads new versions of specific files from GitHub and replaces the local ones.
    """
    update_finished = pyqtSignal(bool, str) # success, message
    update_progress = pyqtSignal(int)

    BASE_URL = "https://raw.githubusercontent.com/ION-FX/ionos/main/apps/mobatuxterm/"
    # List of files to update relative to APP_ROOT_DIR
    FILES_TO_UPDATE = [
        "mobatuxterm.py",
        "mobatuxtermfiles/ssh_worker.py",
        "mobatuxtermfiles/version.txt"
    ]

    def run(self):
        try:
            total_files = len(self.FILES_TO_UPDATE)
            # 1. Download all to .tmp first (safe approach)
            for i, rel_path in enumerate(self.FILES_TO_UPDATE):
                url = self.BASE_URL + rel_path
                local_path = os.path.join(APP_ROOT_DIR, rel_path)
                tmp_path = local_path + ".tmp"

                # Ensure directory exists (important if we add new subfolders later)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)

                # Download
                with urllib.request.urlopen(url, timeout=10) as response, open(tmp_path, 'wb') as out_file:
                    out_file.write(response.read())
                
                # Calculate roughly 50% progress for downloading
                progress = int(((i + 1) / total_files) * 50)
                self.update_progress.emit(progress)

            # 2. If we got here, all downloads succeeded. Perform the swap.
            for i, rel_path in enumerate(self.FILES_TO_UPDATE):
                local_path = os.path.join(APP_ROOT_DIR, rel_path)
                tmp_path = local_path + ".tmp"
                
                # On Linux, os.rename is atomic and can overwrite running files safely
                os.rename(tmp_path, local_path)

                # Calculate remaining 50% progress for installing
                progress = 50 + int(((i + 1) / total_files) * 50)
                self.update_progress.emit(progress)

            self.update_finished.emit(True, "Update successfully installed!\nPlease restart MobaTuxTerm.")

        except Exception as e:
            # Clean up any .tmp files if it failed
            for rel_path in self.FILES_TO_UPDATE:
                 tmp_path = os.path.join(APP_ROOT_DIR, rel_path) + ".tmp"
                 if os.path.exists(tmp_path):
                     try: os.remove(tmp_path)
                     except: pass
            self.update_finished.emit(False, f"Update failed:\n{e}")

class MainWindow(QMainWindow):
    """
    The main application window.
    """
    # --- EXTENSION DEFINITIONS ---
    TEXT_EXTENSIONS = {
        # Config & Data
        '.yml', '.yaml', '.json', '.xml', '.ini', '.conf', '.config', '.cfg', '.toml',
        '.properties', '.csv', '.tsv', '.log', '.sql', '.plist', '.nfo',
        # Web
        '.html', '.htm', '.xhtml', '.css', '.scss', '.sass', '.less', '.js', '.jsx',
        '.ts', '.tsx', '.vue', '.php', '.asp', '.aspx', '.jsp',
        # Scripting & Code
        '.py', '.pyw', '.rb', '.pl', '.pm', '.sh', '.bash', '.zsh', '.fish', '.bat',
        '.cmd', '.ps1', '.psm1', '.vbs', '.lua', '.go', '.rs', '.dart', '.elm', '.erl',
        '.hs', '.lhs', '.ml', '.mli', '.jl', '.nim', '.cr', '.ex', '.exs',
        # C-family
        '.c', '.cpp', '.h', '.hpp', '.cc', '.hh', '.cxx', '.hxx', '.m', '.mm', '.cs',
        '.java', '.kt', '.kts', '.scala', '.groovy', '.swift', '.valas',
        # Documentation & Plain Text
        '.txt', '.md', '.markdown', '.rst', '.tex', '.latex', '.asciidoc', '.adoc',
        '.org', '.me', '.1', '.2', '.3', '.4', '.5', '.6', '.7', '.8',
        # Misc
        '.diff', '.patch', '.lock'
    }

    TEXT_FILENAMES = {
        'dockerfile', 'makefile', 'rakefile', 'gemfile', 'vagrantfile', 'procfile',
        'cmakelists.txt', 'license', 'readme', 'changelog', 'copying', 'install',
        # Dotfiles are best matched as exact filenames
        '.bashrc', '.zshrc', '.profile', '.bash_profile', '.gitconfig', '.vimrc',
        '.nanorc', '.inputrc', '.xinitrc', '.xprofile', '.bash_aliases', '.gitignore',
        '.gitattributes', '.editorconfig', '.env', '.htaccess'
    }

    # Define signals to safely call worker slots from the main thread
    start_connection = pyqtSignal(dict)
    start_list_directory = pyqtSignal(str)
    start_run_command = pyqtSignal(str, str)
    start_download_file = pyqtSignal(str, str)
    start_upload_file = pyqtSignal(str, str)
    start_get_file_content = pyqtSignal(str)
    start_save_file_content = pyqtSignal(str, str)
    start_cancel_task = pyqtSignal()
    start_close_connection = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MobaTuxTerm - for IonOS")
        self.setGeometry(100, 100, 1200, 800)

        self.current_remote_path = ""
        self.local_path = os.path.expanduser("~")

        self.folder_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.file_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

        # --- Threading Setup ---
        self.thread = QThread()
        self.worker = SshWorker()
        self.worker.moveToThread(self.thread)

        # --- Connect Worker Signals to Main GUI Slots ---
        self.worker.error.connect(self.on_error)
        self.worker.connection_ready.connect(self.on_connection_ready)
        self.worker.listing_ready.connect(self.on_listing_ready)
        self.worker.command_output.connect(self.on_command_output)
        self.worker.path_changed.connect(self.on_path_changed)
        self.worker.file_content_ready.connect(self.on_file_content_ready)
        self.worker.task_finished.connect(self.on_task_finished)

        # --- Connect Main GUI Signals to Worker Slots ---
        self.start_connection.connect(self.worker.connect_ssh)
        self.start_list_directory.connect(self.worker.list_directory)
        self.start_run_command.connect(self.worker.run_command)
        self.start_download_file.connect(self.worker.download_file)
        self.start_get_file_content.connect(self.worker.get_file_content)
        self.start_save_file_content.connect(self.worker.save_file_content)
        self.start_cancel_task.connect(self.worker.cancel_task)
        self.start_close_connection.connect(self.worker.close_connection)

        # --- Start the thread ---
        self.thread.start()

        self.init_ui()

        # Disable UI until connected
        self.sftp_browser.setEnabled(False)
        self.terminal_input.setEnabled(False)

        # --- Auto-Update Check ---
        self.update_checker = UpdateChecker()
        self.update_checker.update_available.connect(self.on_update_available)
        self.update_checker.start()

        # Delay session manager slightly to let window init
        QTimer.singleShot(100, self.check_session_manager)

    def check_session_manager(self):
        if not self.show_session_manager():
            sys.exit(0)

    def init_ui(self):
        """
        Initializes the main User Interface components.
        """
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        # --- Main Splitter ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # --- Left Side: SFTP Container ---
        sftp_container = QWidget()
        sftp_layout = QVBoxLayout(sftp_container)
        sftp_layout.setContentsMargins(0, 0, 0, 0) # No padding
        sftp_layout.setSpacing(2) # A little space between path bar and tree

        # 1. Path Bar
        self.sftp_path_bar = QLineEdit()
        self.sftp_path_bar.setFont(QFont("Monospace", 9))
        self.sftp_path_bar.returnPressed.connect(self.navigate_sftp_path)
        self.sftp_path_bar.setPlaceholderText("Current Path...")
        sftp_layout.addWidget(self.sftp_path_bar)

        # 2. SFTP Browser
        self.sftp_browser = QTreeWidget()
        self.sftp_browser.setHeaderLabels(["Name", "Size", "Type", "Permissions"])
        self.sftp_browser.setColumnWidth(0, 300)
        self.sftp_browser.itemDoubleClicked.connect(self.sftp_item_double_clicked)
        self.sftp_browser.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        # self.sftp_browser.customContextMenuRequested.connect(self.sftp_context_menu)
        sftp_layout.addWidget(self.sftp_browser)

        splitter.addWidget(sftp_container)

        # --- Right Side: Terminal ---
        terminal_widget = QWidget()
        terminal_layout = QVBoxLayout(terminal_widget)
        terminal_layout.setContentsMargins(0, 0, 0, 0)

        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Monospace", 10))
        self.terminal_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; border: none;")

        self.terminal_input = QLineEdit()
        self.terminal_input.setFont(QFont("Monospace", 10))
        self.terminal_input.setStyleSheet("background-color: #252526; color: #d4d4d4; border-top: 1px solid #333;")
        self.terminal_input.returnPressed.connect(self.execute_command)

        terminal_layout.addWidget(self.terminal_output)
        terminal_layout.addWidget(self.terminal_input)
        splitter.addWidget(terminal_widget)

        splitter.setSizes([400, 800]) # Initial size ratio

    # --- HELPER: Check if file is text ---
    def is_text_file(self, filename):
        """Determines if a file is likely safely editable text."""
        base = os.path.basename(filename)
        name, ext = os.path.splitext(base)
        # Check if the WHOLE filename is in our allowed list (covers Dockerfile AND .bashrc)
        if base.lower() in self.TEXT_FILENAMES: return True
        # Check if it has an allowed extension (covers test.py)
        if ext.lower() in self.TEXT_EXTENSIONS: return True
        return False

    def navigate_sftp_path(self):
        new_path = self.sftp_path_bar.text().strip()
        if not new_path: return
        self.populate_sftp_browser(new_path)

    def show_session_manager(self):
        dialog = SessionManagerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            session = dialog.get_selected_session()
            if session:
                self.terminal_output.append(f"Connecting to {session['host']}...")
                self.start_connection.emit(session)
                return True
        return False

    def format_size(self, size_in_bytes):
        if size_in_bytes == 0: return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        size = float(size_in_bytes)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f"{size:.1f} {units[i]}"

    def update_terminal_prompt(self):
        prompt = f"[{self.current_remote_path}]$ "
        self.terminal_input.setPlaceholderText(prompt)
        self.terminal_output.moveCursor(self.terminal_output.textCursor().MoveOperation.End)

    @pyqtSlot(str, str)
    def on_connection_ready(self, user_host, initial_path):
        self.current_remote_path = initial_path
        self.setWindowTitle(f"MobaTuxTerm - {user_host}")
        self.sftp_path_bar.setText(self.current_remote_path)
        self.sftp_browser.setEnabled(True)
        self.terminal_input.setEnabled(True)
        self.populate_sftp_browser(self.current_remote_path)
        self.update_terminal_prompt()
        self.terminal_input.setFocus()
        self.execute_command(command_str="echo 'Welcome to MobaTuxTerm!' && uname -a", internal=True)

    @pyqtSlot(str, str)
    def on_error(self, title, message):
        if "Connection" in title:
             QMessageBox.critical(self, title, message)
        self.terminal_output.append(f"<font color='#ff5555'>ERROR: {message}</font>")
        self.sftp_browser.setEnabled(True)
        self.terminal_input.setEnabled(True)

    @pyqtSlot(list, str)
    def on_listing_ready(self, items, new_path):
        self.current_remote_path = new_path
        self.sftp_path_bar.setText(self.current_remote_path)
        self.sftp_browser.clear()

        up_item = QTreeWidgetItem(["..", "", "Parent Directory", ""])
        up_item.setIcon(0, self.folder_icon)
        up_item.setData(0, Qt.ItemDataRole.UserRole, {"is_dir": True, "filename": ".."})
        self.sftp_browser.addTopLevelItem(up_item)

        items.sort(key=lambda x: (not stat.S_ISDIR(x.st_mode), x.filename.lower()))

        for item in items:
            filename = item.filename
            if filename in ('.', '..'): continue
            is_dir = stat.S_ISDIR(item.st_mode)
            # Updated to use is_text_file for better Type column info
            file_type = "Directory" if is_dir else ("Text File" if self.is_text_file(filename) else "File")
            size = self.format_size(item.st_size) if not is_dir else ""
            permissions = stat.filemode(item.st_mode)

            tree_item = QTreeWidgetItem([filename, size, file_type, permissions])
            tree_item.setIcon(0, self.folder_icon if is_dir else self.file_icon)

            tree_item.setData(0, Qt.ItemDataRole.UserRole, {
                "is_dir": is_dir,
                "filename": filename,
                "full_path": os.path.join(self.current_remote_path, filename)
            })
            self.sftp_browser.addTopLevelItem(tree_item)

        self.update_terminal_prompt()
        self.sftp_browser.setEnabled(True)

    @pyqtSlot(str, str)
    def on_command_output(self, stdout, stderr):
        if stdout: self.terminal_output.append(stdout)
        if stderr: self.terminal_output.append(f"<font color='#ffaa00'>{stderr}</font>")
        self.update_terminal_prompt()
        self.terminal_input.setEnabled(True)
        self.terminal_input.setFocus()

    @pyqtSlot(str)
    def on_path_changed(self, new_path):
        self.populate_sftp_browser(new_path)

    @pyqtSlot(str, str)
    def on_task_finished(self, title, message):
        QMessageBox.information(self, title, message)
        self.populate_sftp_browser(self.current_remote_path)

    def populate_sftp_browser(self, path):
        self.sftp_browser.setEnabled(False)
        self.start_list_directory.emit(path)

    def sftp_item_double_clicked(self, item, column):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data: return

        if data["is_dir"]:
            new_path = os.path.normpath(os.path.join(self.current_remote_path, data["filename"]))
            self.populate_sftp_browser(new_path)
        else:
            # Updated double-click logic with text file check
            if self.is_text_file(data["filename"]):
                QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
                self.start_get_file_content.emit(data["full_path"])
            else:
                 QMessageBox.information(self, "Binary File",
                    f"{data['filename']} does not appear to be a text file.\nDouble-click downloading not yet implemented for binaries.")

    @pyqtSlot(str, str)
    def on_file_content_ready(self, remote_path, content_str):
        QApplication.restoreOverrideCursor()
        editor = RemoteTextEditorDialog(remote_path, content_str, self)
        editor.save_requested.connect(self.start_save_file_content)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.populate_sftp_browser(self.current_remote_path)

    def execute_command(self, command_str=None, internal=False):
        command = command_str if command_str is not None else self.terminal_input.text().strip()
        if not command: return

        if not internal:
            self.terminal_output.append(f"<font color='#5a90d6'>[{self.current_remote_path}]$ {command}</font>")
            self.terminal_input.clear()

        blocked_editors = {"nano", "vim", "vi", "emacs"}
        parts = command.split()

        if not internal and parts and parts[0] in blocked_editors:
            if len(parts) < 2:
                 self.terminal_output.append(f"<font color='orange'>Usage: {parts[0]} &lt;filename&gt;</font>")
                 self.update_terminal_prompt()
                 return

            target_file = None
            for part in parts[1:]:
                 if not part.startswith('-'):
                      target_file = part
                      break

            if target_file:
                 # Updated interception logic with text file check
                 if self.is_text_file(target_file):
                      full_path = os.path.normpath(os.path.join(self.current_remote_path, target_file))
                      self.terminal_output.append(f"Opening {target_file} in internal editor...")
                      QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
                      self.start_get_file_content.emit(full_path)
                      return
                 else:
                      self.terminal_output.append(f"<font color='orange'>Warning: {target_file} is not in approved text extensions list. Running normally in terminal.</font>")

        self.terminal_input.setEnabled(False)
        self.start_run_command.emit(command, self.current_remote_path)

    def download_item(self, item):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data: return

        if data["is_dir"]:
             QMessageBox.warning(self, "Not Implemented", "Recursive dir download is a big task! Let's do files first.")
             return
        else:
            remote_path = data["full_path"]
            filename = data["filename"]
            local_dest, _ = QFileDialog.getSaveFileName(self, "Save File", os.path.join(self.local_path, filename))
            if local_dest:
                 self.download_file_with_progress(remote_path, local_dest)

    @pyqtSlot(str)
    def on_update_available(self, new_version):
        """
        SLOT: Called if the UpdateChecker finds a newer version.
        """
        reply = QMessageBox.question(
            self,
            "Update Available",
            f"New version {new_version} available. Update now?\n(App will need a restart after)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.start_app_update()

    def start_app_update(self):
        """Starts the updater thread."""
        self.update_progress_dialog = QProgressDialog("Updating MobaTuxTerm...", None, 0, 100, self)
        self.update_progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.update_progress_dialog.setMinimumDuration(0)
        # Disable cancel button for safety during generic update
        self.update_progress_dialog.setCancelButton(None)

        self.app_updater = AppUpdater()
        self.app_updater.update_progress.connect(self.update_progress_dialog.setValue)
        self.app_updater.update_finished.connect(self.on_update_finished)
        self.app_updater.start()

    @pyqtSlot(bool, str)
    def on_update_finished(self, success, message):
        self.update_progress_dialog.close()
        if success:
             QMessageBox.information(self, "Update Complete", message)
             # Optional: Close app automatically?
             # QApplication.quit()
        else:
             QMessageBox.critical(self, "Update Failed", message)

    def download_file_with_progress(self, remote_path, local_path):
        filename = os.path.basename(remote_path)
        progress = QProgressDialog(f"Downloading {filename}...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0) # Show immediately

        self.worker.file_progress.connect(
            lambda fn, pct: progress.setValue(pct) if fn == filename else None
        )

        progress.canceled.connect(self.start_cancel_task)
        self.start_download_file.emit(remote_path, local_path)

    def closeEvent(self, event):
        self.start_close_connection.emit()
        self.thread.quit()
        self.thread.wait(2000)
        event.accept()

IONOS_DARK_THEME = """
QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: none;
    font-family: Cantarell, "Segoe UI", "Helvetica Neue", "Ubuntu", sans-serif;
}
QMainWindow {
    background-color: #252526;
}
QDialog {
    background-color: #252526;
}

/* --- Tree/List Widgets (SFTP and Session Manager) --- */
QTreeWidget, QListWidget {
    background-color: #252526;
    alternate-background-color: #2a2a2a;
    border: 1px solid #333;
}
QTreeWidget::item:hover, QListWidget::item:hover {
    background-color: #3a70b2; /* Blue from logo */
}
QTreeWidget::item:selected, QListWidget::item:selected {
    background-color: #5a90d6; /* Lighter blue from logo */
    color: #ffffff;
}
QHeaderView::section {
    background-color: #1e1e1e;
    padding: 4px;
    border: 1px solid #333;
}

/* --- Buttons --- */
QPushButton {
    background-color: #3a70b2;
    color: #ffffff;
    padding: 5px 10px;
    border-radius: 3px;
    min-width: 60px;
}
QPushButton:hover {
    background-color: #5a90d6;
}
QPushButton:pressed {
    background-color: #2c5a8c;
}

/* --- Line Edits (Terminal, Path Bar, Dialogs) --- */
QLineEdit {
    background-color: #2d2d2d;
    border: 1px solid #333;
    padding: 3px;
    color: #d4d4d4;
}
QLineEdit:read-only {
    background-color: #252526;
}
QTextEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #333;
}

/* --- Scroll Bars --- */
QScrollBar:vertical {
    border: none;
    background: #252526;
    width: 10px;
    margin: 0px 0px 0px 0px;
}
QScrollBar::handle:vertical {
    background: #5a90d6;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar:horizontal {
    border: none;
    background: #252526;
    height: 10px;
    margin: 0px 0px 0px 0px;
}
QScrollBar::handle:horizontal {
    background: #5a90d6;
    min-width: 20px;
    border-radius: 5px;
}
"""

if __name__ == "__main__":
    app = QApplication(sys.argv)

    app_icon = QIcon(os.path.join(APP_ROOT_DIR, "mobatuxtermfiles", "ionos-logo.png"))
    app.setWindowIcon(app_icon)
    app.setStyleSheet(IONOS_DARK_THEME)
    window = MainWindow() # This now handles the session dialog
    window.show()         # Always show the window
    sys.exit(app.exec())   # Start the application event loop
