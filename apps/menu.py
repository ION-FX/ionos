import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QFormLayout, QLineEdit,
    QPushButton, QFileDialog, QComboBox, QCheckBox, QMessageBox,
    QHBoxLayout, QLabel
)
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtCore import Qt, QSize

# A simple dark theme for the application
# We're setting this to make it look a bit more integrated.
DARK_STYLESHEET = """
QWidget {
    background-color: #343a40;
    color: #f8f9fa;
    font-size: 10pt;
}
QLineEdit, QComboBox {
    background-color: #495057;
    border: 1px solid #6c757d;
    border-radius: 4px;
    padding: 5px;
}
QLineEdit:focus, QComboBox:focus {
    border-color: #007bff;
}
QPushButton {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 8px 12px;
    border-radius: 4px;
}
QPushButton:hover {
    background-color: #0056b3;
}
QPushButton:pressed {
    background-color: #004085;
}
QLabel {
    color: #f8f9fa;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
}
QFormLayout {
    spacing: 10px;
}
"""

class KdeMenuCreator(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("KDE Menu Entry Creator")
        self.setWindowIcon(QIcon.fromTheme("applications-system"))  # Use a system icon
        self.setGeometry(300, 300, 500, 450)

        # Main layout
        main_layout = QVBoxLayout()

        # Form layout for inputs
        form_layout = QFormLayout()
        form_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # --- Widgets ---

        # 1. Application Name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., My Cool App")
        form_layout.addRow("App Name:", self.name_edit)

        # 2. Application Comment (Description)
        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("e.g., A short description of the app")
        form_layout.addRow("Description:", self.comment_edit)

        # 3. Executable Path
        self.exec_edit = QLineEdit()
        self.exec_edit.setPlaceholderText("Click 'Browse' to select...")
        exec_btn = QPushButton("Browse...")
        exec_btn.clicked.connect(self.browse_executable)

        exec_layout = QHBoxLayout()
        exec_layout.addWidget(self.exec_edit)
        exec_layout.addWidget(exec_btn)
        form_layout.addRow("Executable/Script:", exec_layout)

        # 4. Execution Method
        self.exec_method_combo = QComboBox()
        self.exec_method_combo.addItems([
            "Default (./)",  # For binaries or scripts with a shebang
            "python3",
            "python",
            "wine",
            "bash",
            "sh"
        ])
        self.exec_method_combo.setEditable(True)  # Allow custom commands
        self.exec_method_combo.setToolTip("Select or type the command to run the executable with (e.g., 'python3', 'wine')")
        form_layout.addRow("Run with:", self.exec_method_combo)

        # 5. Icon
        self.icon_edit = QLineEdit()
        self.icon_edit.setPlaceholderText("Click 'Browse' to select icon...")
        icon_btn = QPushButton("Browse Icon...")
        icon_btn.clicked.connect(self.browse_icon)

        # Icon Preview
        self.icon_preview = QLabel("Icon")
        self.icon_preview.setFixedSize(64, 64)
        self.icon_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_preview.setStyleSheet("border: 1px dashed #6c757d; border-radius: 4px;")

        icon_layout = QHBoxLayout()
        icon_layout.addWidget(self.icon_edit)
        icon_layout.addWidget(icon_btn)

        icon_form_layout = QVBoxLayout()
        icon_form_layout.addLayout(icon_layout)
        icon_form_layout.addWidget(self.icon_preview, 0, Qt.AlignmentFlag.AlignRight)

        form_layout.addRow("Icon:", icon_form_layout)

        # 6. Working Path
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Autofilled, or click 'Browse'...")
        path_btn = QPushButton("Browse Path...")
        path_btn.clicked.connect(self.browse_path)

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(path_btn)
        form_layout.addRow("Working Path:", path_layout)

        # 7. Category
        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "Utility",
            "Development",
            "Game",
            "Graphics",
            "Office",
            "Network",
            "AudioVideo",
            "System",
            "Education",
            "Science"
        ])
        form_layout.addRow("Category:", self.category_combo)

        # 8. Run in Terminal
        self.terminal_check = QCheckBox("Run in terminal?")
        self.terminal_check.setToolTip("Check this for command-line applications")

        # 9. Save Button
        self.save_btn = QPushButton("Create Menu Entry")
        self.save_btn.clicked.connect(self.save_desktop_file)
        self.save_btn.setIcon(QIcon.fromTheme("document-save"))

        # --- Assemble Layout ---
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.terminal_check, 0, Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch(1) # Add stretchable space
        main_layout.addWidget(self.save_btn)

        self.setLayout(main_layout)

    def browse_executable(self):
        """Opens a file dialog to select the main executable or script."""
        file_path, _ = QFileDialog.getOpenFileName(self,
                                                   "Select Executable or Script",
                                                   "",
                                                   "All Files (*);;AppImages (*.AppImage *.appimage);;Python Scripts (*.py);;Shell Scripts (*.sh)")
        if file_path:
            self.exec_edit.setText(file_path)

            # --- Good UX: Auto-fill other fields ---
            # 1. Set working path to the file's directory
            dir_path = os.path.dirname(file_path)
            self.path_edit.setText(dir_path)

            # 2. Set name to the filename (without extension)
            base_name = os.path.basename(file_path)
            app_name, ext = os.path.splitext(base_name)
            self.name_edit.setText(app_name.replace('-', ' ').replace('_', ' ').title())

            # 3. Auto-select execution method based on extension
            ext_lower = ext.lower()
            if ext_lower == '.appimage':
                self.exec_method_combo.setCurrentText("Default (./)")
            elif ext_lower == '.py':
                self.exec_method_combo.setCurrentText("python3")
            elif ext_lower == '.sh':
                self.exec_method_combo.setCurrentText("bash")
            else:
                # For binaries or unknown, default is fine
                self.exec_method_combo.setCurrentText("Default (./)")

    def browse_icon(self):
        """Opens a file dialog to select an icon."""
        icon_path, _ = QFileDialog.getOpenFileName(self, "Select Icon", "", "Images (*.png *.svg *.xpm *.ico)")
        if icon_path:
            self.icon_edit.setText(icon_path)

            # Update the preview
            pixmap = QPixmap(icon_path)
            if not pixmap.isNull():
                self.icon_preview.setPixmap(pixmap.scaled(
                    64, 64,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                ))
            else:
                self.icon_preview.setText("Invalid")

    def browse_path(self):
        """Opens a directory dialog to select the working path."""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Working Directory")
        if dir_path:
            self.path_edit.setText(dir_path)

    def save_desktop_file(self):
        """Validates inputs and saves the .desktop file."""

        # 1. Get all values
        name = self.name_edit.text().strip()
        comment = self.comment_edit.text().strip()
        executable = self.exec_edit.text().strip()
        exec_method = self.exec_method_combo.currentText().strip()
        icon = self.icon_edit.text().strip()
        path = self.path_edit.text().strip()
        category = self.category_combo.currentText()
        terminal = self.terminal_check.isChecked()

        # 2. Validation
        if not name or not executable:
            QMessageBox.warning(self, "Missing Info", "Please fill in at least the 'App Name' and 'Executable' fields.")
            return

        # 3. Construct the 'Exec' command
        # We quote the executable path to handle spaces
        if exec_method == "Default (./)":
            # AppImages and binaries often need to be executable
            # We can try to set it, though it might fail if user doesn't own the file
            try:
                os.chmod(executable, 0o755)
            except Exception as e:
                print(f"Could not set executable bit: {e}") # Log to console, but don't stop

            exec_command = f'"{executable}"'
        else:
            exec_command = f'{exec_method} "{executable}"'

        # 4. Construct the .desktop file content
        content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name={name}
Comment={comment}
Exec={exec_command}
Icon={icon}
Path={path}
Terminal={'true' if terminal else 'false'}
Categories={category};
"""

        # 5. Determine save path
        # We create a "safe" filename based on the app name
        safe_name = name.lower().replace(" ", "-")
        # Remove any characters that aren't letters, numbers, or dashes
        safe_name = "".join(c for c in safe_name if c.isalnum() or c == '-')

        if not safe_name:
            safe_name = "custom-app" # Fallback

        save_dir = os.path.expanduser("~/.local/share/applications")
        os.makedirs(save_dir, exist_ok=True)  # Ensure the directory exists

        save_path = os.path.join(save_dir, f"{safe_name}.desktop")

        # 6. Write the file
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)

            # Set file permissions (read/write for user, read for group/others)
            # This isn't strictly needed for it to show up, but it's good practice.
            os.chmod(save_path, 0o644)

            # 7. Refresh the KDE menu database
            # This makes the new entry show up immediately
            os.system(f"update-desktop-database -q {save_dir} &")

            QMessageBox.information(self, "Success!",
                                    f"Menu entry created successfully!\n\n"
                                    f"It was saved to:\n{save_path}\n\n"
                                    "It should appear in your menu shortly.")

            # Optional: Clear fields for next entry
            self.name_edit.clear()
            self.comment_edit.clear()
            self.exec_edit.clear()
            self.icon_edit.clear()
            self.path_edit.clear()
            self.icon_preview.clear()
            self.icon_preview.setText("Icon")
            self.terminal_check.setChecked(False)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {e}")


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)  # Apply the dark theme

    window = KdeMenuCreator()
    window.show()

    sys.exit(app.exec())

if __name__ == '__main__':
    main()

