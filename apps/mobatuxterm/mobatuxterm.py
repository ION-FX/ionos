import sys
import os
import stat
import paramiko
import io
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit, QLineEdit,
    QDialog, QFormLayout, QPushButton, QDialogButtonBox,
    QMessageBox, QStyle, QMenu, QFileDialog, QProgressDialog,
    QListWidget, QListWidgetItem, QInputDialog
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSlot, pyqtSignal
from mobatuxtermfiles.ssh_worker import SshWorker

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

        # --- THIS IS THE MISSING UI CODE ---
        layout = QVBoxLayout(self)

        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Monospace", 10))
        layout.addWidget(self.text_edit)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        layout.addWidget(self.buttons)
        # --- END OF MISSING UI CODE ---

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
        # We don't show success/error here. The MainWindow will.
        self.accept() # Close the dialog

class SessionManagerDialog(QDialog):
    """
    Manages loading, creating, and deleting sessions.
    Also handles the master password.
    """
    # Define the directory
    CONFIG_DIR = "mobatuxtermfiles"
    SESSIONS_FILE = os.path.join(CONFIG_DIR, "mobatuxterm_sessions.json")

    def __init__(self, parent=None):
        # Ensure the config directory exists
        os.makedirs(self.CONFIG_DIR, exist_ok=True)
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

class MainWindow(QMainWindow):
    """
    The main application window.
    """
    # Define signals to safely call worker slots from the main thread
    # This is the cleanest, most thread-safe way.
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

        # Remove these! The worker will manage them.
        # self.ssh_client = None
        # self.sftp_client = None
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
        # This ensures the worker's slots are called on the worker's thread
        self.start_connection.connect(self.worker.connect_ssh)
        self.start_list_directory.connect(self.worker.list_directory)
        self.start_run_command.connect(self.worker.run_command)
        self.start_download_file.connect(self.worker.download_file)
        # ... add connects for upload, delete, mkdir, etc. ...
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

        # Show session manager *after* __init__ is done
        if not self.show_session_manager():
            sys.exit(0)
    def init_ui(self):
        """
        Initializes the main User Interface components.
        This can safely run before a connection is established.
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

        # 1. The new Path Bar
        self.sftp_path_bar = QLineEdit()
        self.sftp_path_bar.setFont(QFont("Monospace", 9))
        self.sftp_path_bar.returnPressed.connect(self.navigate_sftp_path) # <-- ADD this line
        self.sftp_path_bar.setPlaceholderText("Current Path...")
        sftp_layout.addWidget(self.sftp_path_bar)

        # 2. The existing SFTP Browser
        self.sftp_browser = QTreeWidget()
        self.sftp_browser.setHeaderLabels(["Name", "Size", "Type", "Permissions"])
        self.sftp_browser.setColumnWidth(0, 300)
        self.sftp_browser.itemDoubleClicked.connect(self.sftp_item_double_clicked)
        self.sftp_browser.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        # self.sftp_browser.customContextMenuRequested.connect(self.sftp_context_menu) # You'll need to re-link this
        sftp_layout.addWidget(self.sftp_browser)

        # 3. Add the *container* to the splitter
        splitter.addWidget(sftp_container)

        # --- Right Side: Terminal ---
        terminal_widget = QWidget()
        terminal_layout = QVBoxLayout(terminal_widget)
        terminal_layout.setContentsMargins(0, 0, 0, 0)

        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Monospace", 10))
        self.terminal_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")

        self.terminal_input = QLineEdit()
        self.terminal_input.setFont(QFont("Monospace", 10))
        self.terminal_input.setStyleSheet("background-color: #252526; color: #d4d4d4; border: 1px solid #333;")
        self.terminal_input.returnPressed.connect(self.execute_command)

        terminal_layout.addWidget(self.terminal_output)
        terminal_layout.addWidget(self.terminal_input)
        splitter.addWidget(terminal_widget)

        splitter.setSizes([400, 800]) # Initial size ratio

    def navigate_sftp_path(self):
        """
        Called when the user presses Enter in the SFTP path bar.
        """
        new_path = self.sftp_path_bar.text().strip()
        if not new_path:
            # If it's empty, do nothing
            return

        # We can just call populate_sftp_browser!
        # It already disables the GUI, emits the signal to the worker,
        # and handles the results.
        self.populate_sftp_browser(new_path)

    def show_session_manager(self):
        """
        Shows the session manager. If a session is chosen,
        it *signals* the worker to connect.
        """
        dialog = SessionManagerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            session = dialog.get_selected_session()
            if session:
                # --- THIS IS THE KEY CHANGE ---
                # We don't call connect_ssh directly. We emit a signal.
                self.terminal_output.append(f"Connecting to {session['host']}...")
                self.start_connection.emit(session)
                return True
        return False

    def format_size(self, size_in_bytes):
        """Converts bytes to a human-readable string (KB, MB, GB)."""
        if size_in_bytes == 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        size = float(size_in_bytes)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        # Format to one decimal place, e.g., "1.2 MB"
        return f"{size:.1f} {units[i]}"

    def update_terminal_prompt(self):
        """
        Updates the terminal prompt display.
        (This is just visual, the real path is tracked internally)
        """
        prompt = f"[{self.current_remote_path}]$ "
        self.terminal_input.setPlaceholderText(prompt)
        # Ensure the cursor in the output window is at the end
        self.terminal_output.moveCursor(self.terminal_output.textCursor().MoveOperation.End)
    # REMOVE connect_ssh() - The worker does this now.

    # ... init_ui() is unchanged ...

    # REMOVE post_connection_setup() - This logic moves to on_connection_ready()

    # --- New GUI Slots to Receive Worker Signals ---

    @pyqtSlot(str, str)
    def on_connection_ready(self, user_host, initial_path):
        """
        SLOT: Called by worker when connection is established.
        This is the *new* 'post_connection_setup'.
        """
        self.current_remote_path = initial_path
        self.setWindowTitle(f"MobaTuxTerm - {user_host}")
        self.sftp_path_bar.setText(self.current_remote_path)

        # Enable UI
        self.sftp_browser.setEnabled(True)
        self.terminal_input.setEnabled(True)

        # Request initial directory listing
        self.populate_sftp_browser(self.current_remote_path)

        self.update_terminal_prompt()
        self.terminal_input.setFocus()

        # Run welcome command
        self.execute_command(command_str="echo 'Welcome to MobaTuxTerm!' && uname -a", internal=True)

    @pyqtSlot(str, str)
    def on_error(self, title, message):
        """
        SLOT: Called by worker when any error occurs.
        """
        QMessageBox.critical(self, title, message)
        self.terminal_output.append(f"<font color='red'>ERROR: {message}</font>")
        # Re-enable UI if it was locked
        self.sftp_browser.setEnabled(True)
        self.terminal_input.setEnabled(True)

    @pyqtSlot(list, str)
    def on_listing_ready(self, items, new_path):
        """
        SLOT: Called by worker when directory listing is ready.
        This contains the GUI logic from your old 'populate_sftp_browser'.
        """
        self.current_remote_path = new_path
        self.sftp_path_bar.setText(self.current_remote_path)
        self.sftp_browser.clear()

        # Add ".." item to go up
        up_item = QTreeWidgetItem(["..", "", "Parent Directory", ""])
        up_item.setIcon(0, self.folder_icon)
        up_item.setData(0, Qt.ItemDataRole.UserRole, {"is_dir": True, "filename": ".."})
        self.sftp_browser.addTopLevelItem(up_item)

        items.sort(key=lambda x: (not stat.S_ISDIR(x.st_mode), x.filename.lower()))

        for item in items:
            filename = item.filename
            if filename in ('.', '..'):
                continue

            is_dir = stat.S_ISDIR(item.st_mode)
            file_type = "Directory" if is_dir else "File"
            size = self.format_size(item.st_size) if not is_dir else ""
            permissions = stat.filemode(item.st_mode)

            tree_item = QTreeWidgetItem([filename, size, file_type, permissions])
            tree_item.setIcon(0, self.folder_icon if is_dir else self.file_icon)

            item_data = {
                "is_dir": is_dir,
                "filename": filename,
                "full_path": os.path.join(self.current_remote_path, filename) # Use os.path.join
            }
            tree_item.setData(0, Qt.ItemDataRole.UserRole, item_data)
            self.sftp_browser.addTopLevelItem(tree_item)

        self.update_terminal_prompt()
        self.sftp_browser.setEnabled(True) # Re-enable after load

    @pyqtSlot(str, str)
    def on_command_output(self, stdout, stderr):
        """
        SLOT: Called by worker when a command finishes.
        """
        if stdout:
            self.terminal_output.append(stdout)
        if stderr:
            self.terminal_output.append(f"<font color='orange'>STDERR: {stderr}</font>")
        self.update_terminal_prompt()
        self.terminal_input.setEnabled(True)

    @pyqtSlot(str)
    def on_path_changed(self, new_path):
        """
        SLOT: Called by worker after a successful 'cd' command.
        """
        self.terminal_output.append(f"Path changed to: {new_path}")
        self.populate_sftp_browser(new_path) # This will trigger a new listing

    @pyqtSlot(str, str)
    def on_task_finished(self, title, message):
        """
        SLOT: Called by worker for simple success notifications.
        """
        QMessageBox.information(self, title, message)
        # Refresh browser after any task that might change files
        self.populate_sftp_browser(self.current_remote_path)

    # --- Now, modify your action methods to *emit signals* ---

    def populate_sftp_browser(self, path):
        """
        This method NO LONGER does the work.
        It just disables the GUI and asks the worker to do the work.
        """
        self.sftp_browser.setEnabled(False) # Disable during load
        self.terminal_output.append(f"Listing {path}...")
        self.start_list_directory.emit(path)

    def sftp_item_double_clicked(self, item, column):
        """
        This method NO LONGER does the work.
        It just asks the worker to do the work.
        """
        item_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_data:
            return

        if item_data["is_dir"]:
            filename = item_data["filename"]
            # Use os.path.join for robust path handling
            new_path = os.path.normpath(os.path.join(self.current_remote_path, filename))
            self.populate_sftp_browser(new_path) # Ask worker to list new path
        else:
            # Ask worker to get file content
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            self.start_get_file_content.emit(item_data["full_path"])

    @pyqtSlot(str, str)
    def on_file_content_ready(self, remote_path, content_str):
        """
        SLOT: Called by worker when file content is ready for editing.
        """
        QApplication.restoreOverrideCursor() # Restore cursor

        # Pass the remote_path and content to the editor
        # The editor can now be dumber. It just needs to emit a signal on save.
        editor = RemoteTextEditorDialog(remote_path, content_str, self)

        # Connect the editor's save signal to our signal
        editor.save_requested.connect(self.start_save_file_content)

        if editor.exec() == QDialog.DialogCode.Accepted:
            # Refresh the SFTP browser to show new size/date
            self.populate_sftp_browser(self.current_remote_path)

    def execute_command(self, command_str=None, internal=False):
        """
        Executes a command on the remote server via SSH.
        This now intercepts 'nano' and other editors.
        """
        if command_str is None:
            command = self.terminal_input.text().strip()
        else:
            command = command_str

        if not command:
            return

        if not internal:
            self.terminal_output.append(f"[{self.current_remote_path}]$ {command}")
            self.terminal_input.clear()

        # --- NEW: Interception Logic ---
        blocked_editors = ["nano", "vim", "vi", "emacs"]
        command_parts = command.split()

        if command_parts and command_parts[0] in blocked_editors:
            # This is a terminal editor command, let's intercept it.
            if len(command_parts) < 2:
                self.terminal_output.append(f"<font color='orange'>Usage: {command_parts[0]} &lt;filename&gt;</font>")
                self.update_terminal_prompt()
                return

            filename = command_parts[1]
            # Resolve the full path
            full_path = os.path.normpath(os.path.join(self.current_remote_path, filename))

            self.terminal_output.append(f"Opening {filename} in GUI editor...")

            # Use the *exact same logic* as sftp_item_double_clicked
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            self.start_get_file_content.emit(full_path)

            # Note: We don't disable terminal_input here, because
            # on_file_content_ready will show a dialog which is modal.

        else:
            # --- This is the ORIGINAL logic for all other commands ---
            # It's not an editor, so run it normally.
            self.terminal_input.setEnabled(False) # Disable until command finishes
            self.start_run_command.emit(command, self.current_remote_path)

        # We move this here, as the 'editor' path doesn't update it.
        if not internal and not (command_parts and command_parts[0] in blocked_editors):
             pass # Already handled by on_command_output
        elif internal:
             pass # Handled by on_command_output
        else:
            self.update_terminal_prompt()
    def download_item(self, item):
        # ... (Get local_dest as you did before) ...
        if is_dir:
            # Recursive dir download is more complex,
            # let's focus on a single file first.
            QMessageBox.warning(self, "Not Implemented", "Recursive dir download is a big task! Let's do files first.")
            return
        else:
            # This is a file download
            self.download_file_with_progress(remote_path, local_dest)

    def download_file_with_progress(self, remote_path, local_path):
        """
        Creates a progress dialog and asks the worker to start downloading.
        """
        filename = os.path.basename(remote_path)
        progress = QProgressDialog(f"Downloading {filename}...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)

        # Connect worker progress signal to dialog
        self.worker.file_progress.connect(
            lambda fn, pct: progress.setValue(pct) if fn == filename else None
        )

        # Connect worker finished signal to close dialog
        # (Need a more robust way to tie this specific task to this dialog)
        # For now, let's just have the progress hit 100.

        # Connect the dialog's cancel button to the worker's cancel slot
        progress.canceled.connect(self.start_cancel_task)

        # Ask worker to start
        self.start_download_file.emit(remote_path, local_path)

    # ... (repeat this pattern for upload_files, delete_item, etc.) ...

    def closeEvent(self, event):
        """
        Handles the window close event to safely close connections
        by asking the worker thread to do it and then quitting the thread.
        """
        self.start_close_connection.emit() # Tell worker to close connections
        self.thread.quit() # Tell the thread's event loop to stop
        self.thread.wait() # Wait for thread to finish cleanly
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

    app_icon = QIcon(os.path.join("mobatuxtermfiles", "ionos-logo.png"))
    app.setWindowIcon(app_icon)
    app.setStyleSheet(IONOS_DARK_THEME)
    window = MainWindow() # This now handles the session dialog
    window.show()         # Always show the window
    sys.exit(app.exec())   # Start the application event loop

