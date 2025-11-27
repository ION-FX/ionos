import paramiko
import time
import socket
import os
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot, QTimer

class SshWorker(QObject):
    """
    Handles all Paramiko network operations in a separate thread.
    Includes both SFTP (File Transfer) and Shell (Terminal) support.
    """

    # --- Signals ---
    error = pyqtSignal(str, str) # title, message
    connection_ready = pyqtSignal(str, str) # user@host, initial_path
    listing_ready = pyqtSignal(list, str) # list of items, new_path

    # Terminal Signals
    shell_data_received = pyqtSignal(str)

    # File/SFTP Signals
    path_changed = pyqtSignal(str)
    file_content_ready = pyqtSignal(str, str) # remote_path, content
    file_progress = pyqtSignal(str, int) # filename, percentage
    task_finished = pyqtSignal(str, str) # title, message

    def __init__(self):
        super().__init__()
        self.ssh_client = None
        self.sftp_client = None
        self.shell_channel = None
        self._is_running = True
        self.shell_timer = None # Initialize as None first

    @pyqtSlot(dict)
    def connect_ssh(self, session):
        """
        Establishes SSH/SFTP connection and starts the Shell.
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=session['host'],
                port=session['port'],
                username=session['user'],
                password=session['password'],
                timeout=10
            )

            # 1. Open SFTP for the file tree
            self.sftp_client = self.ssh_client.open_sftp()
            initial_path = self.sftp_client.getcwd() or "."

            # 2. Open Shell for the Terminal
            self.start_shell()

            user_host = f"{session['user']}@{session['host']}"
            self.connection_ready.emit(user_host, initial_path)

        except Exception as e:
            self.error.emit("Connection Error", str(e))

    def start_shell(self):
        """Opens a persistent TTY shell and starts the polling timer."""
        try:
            self.shell_channel = self.ssh_client.invoke_shell()
            self.shell_channel.setblocking(0) # Non-blocking mode

            # --- FIX: Create Timer HERE, inside the running thread ---
            if self.shell_timer is not None:
                self.shell_timer.stop()
                self.shell_timer.deleteLater()

            self.shell_timer = QTimer()
            self.shell_timer.timeout.connect(self.poll_shell)
            self.shell_timer.start(10) # Poll every 10ms

        except Exception as e:
            self.error.emit("Shell Error", f"Could not start shell: {e}")

    def poll_shell(self):
        """
        Called by QTimer to check for new terminal output.
        """
        if not self.shell_channel or self.shell_channel.closed:
            return

        try:
            if self.shell_channel.recv_ready():
                # Read 4KB chunks
                data = self.shell_channel.recv(4096)
                try:
                    text = data.decode('utf-8')
                except UnicodeDecodeError:
                    text = data.decode('latin-1', errors='ignore')

                self.shell_data_received.emit(text)

            if self.shell_channel.exit_status_ready():
                if self.shell_timer: self.shell_timer.stop()

        except socket.timeout:
            pass
        except Exception:
            if self.shell_timer: self.shell_timer.stop()

    @pyqtSlot(str, str)
    def run_command(self, command, current_path):
        """
        Sends keystrokes/commands to the active shell.
        """
        if self.shell_channel and self.shell_channel.active:
            # We add a newline to simulate pressing Enter
            self.shell_channel.send(command + "\n")
        else:
            self.error.emit("Error", "Shell not active")

    # --- NEW: RAW SEND (For Ctrl+C) ---
    @pyqtSlot(str)
    def send_raw(self, text):
        """
        Sends raw text/bytes to the shell without appending a newline.
        Used for Ctrl+C, Ctrl+Z, etc.
        """
        if self.shell_channel and self.shell_channel.active:
            self.shell_channel.send(text)

    # --- SFTP METHODS ---

    @pyqtSlot(str)
    def list_directory(self, path):
        if not self.sftp_client: return
        try:
            self.sftp_client.chdir(path)
            new_path = self.sftp_client.getcwd()
            items = self.sftp_client.listdir_attr('.')
            self.listing_ready.emit(items, new_path)
        except Exception as e:
            self.error.emit("SFTP Error", str(e))

    @pyqtSlot(str, str)
    def download_file(self, remote_path, local_path):
        self._is_running = True
        filename = os.path.basename(remote_path)

        def progress_callback(sent, total):
            if not self._is_running:
                raise InterruptedError("Download cancelled")
            if total > 0:
                self.file_progress.emit(filename, int(sent / total * 100))

        try:
            file_size = self.sftp_client.stat(remote_path).st_size
            if file_size == 0:
                self.sftp_client.get(remote_path, local_path)
                self.file_progress.emit(filename, 100)
            else:
                self.sftp_client.get(remote_path, local_path, callback=progress_callback)

            if self._is_running:
                self.task_finished.emit("Download Complete", f"Downloaded {filename}")

        except InterruptedError:
            if os.path.exists(local_path):
                os.remove(local_path)
        except Exception as e:
            self.error.emit("Download Error", f"Failed to download {filename}:\n{e}")

    @pyqtSlot(str)
    def get_file_content(self, remote_path):
        """
        Worker slot to fetch file content.
        If file doesn't exist, returns empty string (New File mode).
        """
        try:
            # 1. Check if file exists
            exists = False
            try:
                self.sftp_client.stat(remote_path)
                exists = True
            except IOError:
                pass # File likely doesn't exist

            # 2. Read or Create Empty
            if exists:
                with self.sftp_client.open(remote_path, 'r') as f:
                    content_bytes = f.read()
                try:
                    content_str = content_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    content_str = content_bytes.decode('latin-1')
            else:
                # File missing? No problem. Open empty editor.
                content_str = ""

            self.file_content_ready.emit(remote_path, content_str)

        except Exception as e:
            self.error.emit("File Open Error", f"Could not read {remote_path}:\n{e}")

    @pyqtSlot(str, str)
    def save_file_content(self, remote_path, content):
        try:
            content_bytes = content.encode('utf-8')
            with self.sftp_client.open(remote_path, 'w') as f:
                f.write(content_bytes)
            self.task_finished.emit("Save Successful", f"Successfully saved {remote_path}")
        except Exception as e:
            self.error.emit("Save Error", f"Could not save file:\n{e}")

    @pyqtSlot()
    def cancel_task(self):
        self._is_running = False

    @pyqtSlot()
    def close_connection(self):
        self._is_running = False
        if self.shell_timer:
            self.shell_timer.stop()
        if self.sftp_client: self.sftp_client.close()
        if self.ssh_client: self.ssh_client.close()
