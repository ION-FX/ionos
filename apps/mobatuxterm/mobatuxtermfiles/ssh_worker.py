# SshWorker Class (Add this to your file)
# We need to import these at the top
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot
import paramiko
import os
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

class SshWorker(QObject):
    """
    Handles all Paramiko network operations in a separate thread.
    NEVER interacts with the GUI directly. Uses signals only.
    """

    # --- Signals to send data/status back to the MainWindow ---
    error = pyqtSignal(str, str) # title, message
    connection_ready = pyqtSignal(str, str) # user@host, initial_path

    listing_ready = pyqtSignal(list, str) # list of SFTPAttributes, new_path

    command_output = pyqtSignal(str, str) # stdout, stderr
    path_changed = pyqtSignal(str) # For 'cd' command

    file_content_ready = pyqtSignal(str, str) # remote_path, content

    file_progress = pyqtSignal(str, int) # filename, percentage
    task_finished = pyqtSignal(str, str) # title, message (for success popups)

    def __init__(self):
        super().__init__()
        self.ssh_client = None
        self.sftp_client = None
        self._is_running = True # For cancelling tasks

    @pyqtSlot(dict)
    def connect_ssh(self, session):
        """
        Worker slot to establish the SSH/SFTP connection.
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=session['host'],
                port=session['port'],
                username=session['user'],
                password=session['password'],
                timeout=5
            )

            self.sftp_client = self.ssh_client.open_sftp()
            initial_path = self.sftp_client.getcwd()
            if initial_path is None:
                initial_path = self.sftp_client.normalize('.')

            user_host = f"{session['user']}@{session['host']}"
            self.connection_ready.emit(user_host, initial_path)

        except Exception as e:
            self.error.emit("Connection Error", f"Could not connect to {session['host']}:{session['port']}\n{e}")

    @pyqtSlot(str)
    def list_directory(self, path):
        """
        Worker slot to get a directory listing.
        """
        if not self.sftp_client:
            return
        try:
            self.sftp_client.chdir(path)
            new_path = self.sftp_client.getcwd()
            items = self.sftp_client.listdir_attr('.')
            self.listing_ready.emit(items, new_path)
        except Exception as e:
            self.error.emit("SFTP Error", f"Could not list directory {path}:\n{e}")

    @pyqtSlot(str, str)
    def run_command(self, command, current_path):
        """
        Worker slot to execute a shell command.
        """
        if not self.ssh_client:
            return

        try:
            # Handle 'cd' logic
            if command.startswith("cd "):
                new_path = command.split(" ", 1)[1].strip()
                full_cd_command = f"cd {current_path} && cd {new_path} && pwd"

                stdin, stdout, stderr = self.ssh_client.exec_command(full_cd_command)
                new_cwd = stdout.read().decode().strip()
                err = stderr.read().decode().strip()

                if new_cwd and not err:
                    # 'cd' was successful, emit signal to change path
                    self.path_changed.emit(new_cwd)
                elif err:
                    self.command_output.emit("", err)
            else:
                # Normal command
                full_command = f"cd {current_path} && {command}"
                stdin, stdout, stderr = self.ssh_client.exec_command(full_command, get_pty=True)

                output = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                self.command_output.emit(output, err)

        except Exception as e:
            self.error.emit("Command Error", f"Command execution failed:\n{e}")

    @pyqtSlot(str, str)
    def download_file(self, remote_path, local_path):
        """
        Worker slot to download a file.
        """
        self._is_running = True
        filename = os.path.basename(remote_path)

        def progress_callback(sent, total):
            if not self._is_running:
                raise InterruptedError("Download cancelled by user.")
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
            self.command_output.emit(f"Download of {filename} cancelled.", "")
        except Exception as e:
            self.error.emit("Download Error", f"Failed to download {filename}:\n{e}")

    # --- Add UPLOAD, DELETE, MKDIR, GET_CONTENT slots ---
    # (Following the same pattern: get data, do work, emit signals)

    @pyqtSlot(str)
    def get_file_content(self, remote_path):
        """
        Worker slot to fetch file content for the editor.
        """
        try:
            with self.sftp_client.open(remote_path, 'r') as f:
                content_bytes = f.read()
            # Try to decode as UTF-8, fallback to latin-1
            try:
                content_str = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content_str = content_bytes.decode('latin-1')
            self.file_content_ready.emit(remote_path, content_str)
        except Exception as e:
            self.error.emit("File Open Error", f"Could not read {remote_path}:\n{e}")

    @pyqtSlot(str, str)
    def save_file_content(self, remote_path, content):
        """
        Worker slot to save file content from the editor.
        """
        try:
            content_bytes = content.encode('utf-8')
            with self.sftp_client.open(remote_path, 'w') as f:
                f.write(content_bytes)
            self.task_finished.emit("Save Successful", f"Successfully saved {remote_path}")
        except Exception as e:
            self.error.emit("Save Error", f"Could not save file:\n{e}")

    @pyqtSlot()
    def cancel_task(self):
        """
        Sets a flag to stop the current long-running task.
        """
        self._is_running = False

    @pyqtSlot()
    def close_connection(self):
        """
        Worker slot to safely close connections.
        """
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
