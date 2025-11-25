import sys
import os
import math
import string
import secrets
import hashlib

from typing import List, Tuple

from PyQt5 import QtWidgets, QtCore, QtGui


# =========================
#   CORE PASSWORD ENGINE
# =========================

class PasswordGeneratorCore:
    """
    High-quality, cryptographically secure password generator with
    global uniqueness guarantee using a SHA-256 hash history file.

    - Uses secrets.SystemRandom for secure randomness.
    - Saves SHA-256 hashes of generated passwords in a file located in
      the user's home directory.
    - Refuses to regenerate a password that was already produced before.
    """

    def __init__(self, history_file: str | None = None) -> None:
        if history_file is None:
            home = os.path.expanduser("~")
            history_file = os.path.join(home, ".unique_password_hashes.txt")

        self.history_file = history_file
        self.used_hashes: set[str] = set()
        self._rng = secrets.SystemRandom()
        self._load_history()

    def _load_history(self) -> None:
        if not os.path.exists(self.history_file):
            return
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                for line in f:
                    h = line.strip()
                    if h:
                        self.used_hashes.add(h)
        except (IOError, OSError):
            # If reading fails, we simply don't enforce cross-session history,
            # but this should be very rare on a normal system.
            pass

    def _append_hash(self, pwd_hash: str) -> None:
        try:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(pwd_hash + "\n")
        except (IOError, OSError):
            # Not fatal for current session; still unique in memory.
            pass

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    # ---------- MATH / ENTROPY / SECURITY ESTIMATES ----------

    @staticmethod
    def estimate_entropy(length: int, alphabet_size: int) -> float:
        """Return Shannon entropy (in bits) for a uniformly random password."""
        if length <= 0 or alphabet_size <= 1:
            return 0.0
        return length * math.log2(alphabet_size)

    @staticmethod
    def classify_strength(entropy_bits: float) -> str:
        """Return a human-readable strength label based on entropy."""
        if entropy_bits < 40:
            return "Very weak"
        elif entropy_bits < 60:
            return "Weak"
        elif entropy_bits < 80:
            return "Reasonable"
        elif entropy_bits < 100:
            return "Strong"
        else:
            return "Very strong"

    @staticmethod
    def format_bruteforce_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
        """
        Estimate brute-force time using entropy and a guesses-per-second budget.
        Works in log-space to avoid overflow.
        """
        if entropy_bits <= 0:
            return "< 1 second at 10^10 guesses/second."

        # Expected time ~ (2^(entropy_bits - 1)) / guesses_per_second
        log2_time_seconds = entropy_bits - math.log2(2.0 * guesses_per_second)

        if log2_time_seconds < 0:
            return "< 1 second at 10^10 guesses/second."

        log10_time_seconds = log2_time_seconds * math.log10(2.0)
        seconds_per_year = 60.0 * 60.0 * 24.0 * 365.25
        log10_seconds_per_year = math.log10(seconds_per_year)
        log10_years = log10_time_seconds - log10_seconds_per_year

        if log10_years < -2:
            # < 0.01 years: show days
            log10_days = log10_time_seconds - math.log10(60.0 * 60.0 * 24.0)
            approx_days = 10.0 ** log10_days
            return f"≈ {approx_days:.1f} days at 10^10 guesses/second."
        elif log10_years < 2:
            approx_years = 10.0 ** log10_years
            return f"≈ {approx_years:.2f} years at 10^10 guesses/second."
        else:
            return f"≈ 10^{log10_years:.1f} years at 10^10 guesses/second."

    # ---------- GENERATION ----------

    def _generate_single(
        self,
        length: int,
        group_char_sets: List[str],
        full_alphabet: str,
        avoid_repeats: bool,
    ) -> str:
        """
        Generate a single password (NOT checking global uniqueness).
        Ensures at least one character from each group.
        """
        if length <= 0:
            raise ValueError("Password length must be positive.")
        if not full_alphabet:
            raise ValueError("Alphabet is empty; no characters to choose from.")
        if len(group_char_sets) > length:
            raise ValueError(
                "Password length is too small to include at least one character "
                "from each selected group."
            )

        full_unique = "".join(sorted(set(full_alphabet)))
        if avoid_repeats and length > len(full_unique):
            raise ValueError(
                "Password length exceeds the number of distinct characters available "
                "while avoiding repetitions."
            )

        # Always start by guaranteeing one char from each selected group.
        chars: List[str] = []

        for group in group_char_sets:
            if not group:
                continue
            chars.append(secrets.choice(group))

        remaining = length - len(chars)

        if avoid_repeats:
            available = list(full_unique)
            for c in chars:
                if c in available:
                    available.remove(c)
            for _ in range(remaining):
                if not available:
                    break
                idx = self._rng.randrange(len(available))
                chars.append(available.pop(idx))
        else:
            for _ in range(remaining):
                chars.append(secrets.choice(full_alphabet))

        self._rng.shuffle(chars)
        return "".join(chars)

    def generate_unique_password(
        self,
        length: int,
        group_char_sets: List[str],
        full_alphabet: str,
        avoid_repeats: bool,
        max_attempts: int = 100000,
    ) -> str:
        """
        Generate a password that has never been produced before by this application
        (based on SHA-256 hash history).
        """
        attempts = 0
        last_error: Exception | None = None

        while attempts < max_attempts:
            attempts += 1
            try:
                pwd = self._generate_single(length, group_char_sets, full_alphabet, avoid_repeats)
            except Exception as e:
                last_error = e
                break

            h = self._hash_password(pwd)
            if h not in self.used_hashes:
                self.used_hashes.add(h)
                self._append_hash(h)
                return pwd

        if last_error is not None:
            raise last_error

        raise RuntimeError(
            "Unable to generate a new unique password after many attempts. "
            "The search space might be exhausted for the chosen settings."
        )


# =========================
#        MAIN WINDOW
# =========================

class MainWindow(QtWidgets.QMainWindow):
    """
    Professional GUI for the password generator.

    Features:
    - Live entropy preview
    - Strength bar
    - Batch generation
    - Session history
    - Settings persistence
    """

    def __init__(self) -> None:
        super().__init__()

        self.core = PasswordGeneratorCore()
        self.settings = QtCore.QSettings("UltraSecureTools", "PasswordGeneratorPro")

        self.setWindowTitle("Ultra Secure Unique Password Generator Pro")
        self.setMinimumSize(900, 550)
        self._apply_global_styles()
        self._build_ui()
        self._load_settings()

    # ---------- UI CONSTRUCTION ----------

    def _build_ui(self) -> None:
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)

        main_layout = QtWidgets.QVBoxLayout(central)

        # Toolbar
        self._build_toolbar()

        # Top area: configuration + output
        top_layout = QtWidgets.QHBoxLayout()
        main_layout.addLayout(top_layout, stretch=3)

        # Left: configuration
        config_group = QtWidgets.QGroupBox("Password Policy")
        top_layout.addWidget(config_group, stretch=2)
        config_layout = QtWidgets.QVBoxLayout(config_group)

        # Length
        length_row = QtWidgets.QHBoxLayout()
        length_label = QtWidgets.QLabel("Length:")
        self.length_spin = QtWidgets.QSpinBox()
        self.length_spin.setRange(6, 128)
        self.length_spin.setValue(16)

        self.length_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.length_slider.setRange(6, 128)
        self.length_slider.setValue(16)

        # Keep spin and slider in sync
        self.length_spin.valueChanged.connect(self.length_slider.setValue)
        self.length_slider.valueChanged.connect(self.length_spin.setValue)

        length_row.addWidget(length_label)
        length_row.addWidget(self.length_spin)
        length_row.addWidget(self.length_slider)
        config_layout.addLayout(length_row)

        # Batch count
        batch_row = QtWidgets.QHBoxLayout()
        batch_label = QtWidgets.QLabel("Generate batch:")
        self.batch_spin = QtWidgets.QSpinBox()
        self.batch_spin.setRange(1, 100)
        self.batch_spin.setValue(1)
        batch_row.addWidget(batch_label)
        batch_row.addWidget(self.batch_spin)
        config_layout.addLayout(batch_row)

        # Character sets
        self.lower_cb = QtWidgets.QCheckBox("Lowercase (a–z)")
        self.upper_cb = QtWidgets.QCheckBox("Uppercase (A–Z)")
        self.digits_cb = QtWidgets.QCheckBox("Digits (0–9)")
        self.symbols_cb = QtWidgets.QCheckBox("Symbols (!@#$...)")

        self.lower_cb.setChecked(True)
        self.upper_cb.setChecked(True)
        self.digits_cb.setChecked(True)
        self.symbols_cb.setChecked(True)

        config_layout.addWidget(self.lower_cb)
        config_layout.addWidget(self.upper_cb)
        config_layout.addWidget(self.digits_cb)
        config_layout.addWidget(self.symbols_cb)

        # Options
        self.exclude_similar_cb = QtWidgets.QCheckBox(
            "Exclude similar characters (0/O, 1/l/I, 5/S, 2/Z, 6/G, 8/B)"
        )
        self.no_repeat_cb = QtWidgets.QCheckBox("Avoid repeated characters in a password")
        config_layout.addWidget(self.exclude_similar_cb)
        config_layout.addWidget(self.no_repeat_cb)

        # Custom characters
        custom_form = QtWidgets.QFormLayout()
        self.custom_chars_edit = QtWidgets.QLineEdit()
        self.custom_chars_edit.setPlaceholderText("Optional: extra characters to include (e.g. _-#@)")
        custom_form.addRow("Custom chars:", self.custom_chars_edit)
        config_layout.addLayout(custom_form)

        # Live metrics preview (before generation)
        self.live_entropy_label = QtWidgets.QLabel(
            "Live entropy preview will update as you change settings."
        )
        self.live_entropy_label.setWordWrap(True)
        config_layout.addWidget(self.live_entropy_label)

        config_layout.addStretch(1)

        # Right: output + metrics
        output_group = QtWidgets.QGroupBox("Output & Security Metrics")
        top_layout.addWidget(output_group, stretch=3)
        output_layout = QtWidgets.QVBoxLayout(output_group)

        mono_font = QtGui.QFont("Consolas")
        mono_font.setStyleHint(QtGui.QFont.TypeWriter)

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setReadOnly(True)
        self.password_edit.setFont(mono_font)
        self.password_edit.setPlaceholderText("Click “Generate” to create a unique password.")
        output_layout.addWidget(self.password_edit)

        # Buttons row
        btn_row = QtWidgets.QHBoxLayout()
        self.generate_btn = QtWidgets.QPushButton("Generate")
        self.copy_btn = QtWidgets.QPushButton("Copy")
        self.clear_btn = QtWidgets.QPushButton("Clear")

        btn_row.addWidget(self.generate_btn)
        btn_row.addWidget(self.copy_btn)
        btn_row.addWidget(self.clear_btn)

        output_layout.addLayout(btn_row)

        # Strength bar + label
        strength_row = QtWidgets.QHBoxLayout()
        self.strength_bar = QtWidgets.QProgressBar()
        self.strength_bar.setRange(0, 128)
        self.strength_bar.setFormat("Strength")
        self.strength_bar.setTextVisible(True)
        self.strength_label = QtWidgets.QLabel("Strength: N/A")

        strength_row.addWidget(self.strength_bar, stretch=3)
        strength_row.addWidget(self.strength_label, stretch=2)
        output_layout.addLayout(strength_row)

        # Detailed metrics
        self.metrics_label = QtWidgets.QLabel(
            "Detailed metrics will appear here after generation."
        )
        self.metrics_label.setWordWrap(True)
        output_layout.addWidget(self.metrics_label)

        # Bottom: session history
        history_group = QtWidgets.QGroupBox("Session History")
        main_layout.addWidget(history_group, stretch=2)
        history_layout = QtWidgets.QVBoxLayout(history_group)

        self.history_edit = QtWidgets.QPlainTextEdit()
        self.history_edit.setReadOnly(True)
        self.history_edit.setFont(mono_font)
        self.history_edit.setPlaceholderText(
            "Each generated password (for this session) will appear here. "
            "Uniqueness is enforced globally using a hash history in your home directory."
        )
        history_layout.addWidget(self.history_edit)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready.")

        # Menu bar
        self._build_menu_bar()

        # Connections
        self.generate_btn.clicked.connect(self.on_generate_clicked)
        self.copy_btn.clicked.connect(self.on_copy_clicked)
        self.clear_btn.clicked.connect(self.on_clear_clicked)

        # Live preview signals
        for w in (
            self.length_spin, self.batch_spin,
            self.lower_cb, self.upper_cb, self.digits_cb, self.symbols_cb,
            self.exclude_similar_cb, self.no_repeat_cb, self.custom_chars_edit
        ):
            if isinstance(w, QtWidgets.QLineEdit):
                w.textChanged.connect(self.update_live_preview)
            else:
                w.valueChanged.connect(self.update_live_preview) if isinstance(
                    w, QtWidgets.QSpinBox
                ) else w.stateChanged.connect(self.update_live_preview)

        # Initial preview
        self.update_live_preview()

    def _build_toolbar(self) -> None:
        toolbar = QtWidgets.QToolBar("Main Toolbar")
        toolbar.setIconSize(QtCore.QSize(20, 20))
        self.addToolBar(toolbar)

        style = self.style()

        gen_action = QtWidgets.QAction(
            style.standardIcon(QtWidgets.QStyle.SP_MediaPlay),
            "Generate password",
            self,
        )
        gen_action.setShortcut("Ctrl+G")
        gen_action.triggered.connect(self.on_generate_clicked)
        toolbar.addAction(gen_action)

        copy_action = QtWidgets.QAction(
            style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton),
            "Copy to clipboard",
            self,
        )
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.on_copy_clicked)
        toolbar.addAction(copy_action)

        clear_action = QtWidgets.QAction(
            style.standardIcon(QtWidgets.QStyle.SP_DialogResetButton),
            "Clear output",
            self,
        )
        clear_action.triggered.connect(self.on_clear_clicked)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        about_action = QtWidgets.QAction(
            style.standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation),
            "About",
            self,
        )
        about_action.triggered.connect(self.show_about_dialog)
        toolbar.addAction(about_action)

    def _build_menu_bar(self) -> None:
        menubar = self.menuBar()

        # File
        file_menu = menubar.addMenu("&File")
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View
        view_menu = menubar.addMenu("&View")
        toggle_history_action = QtWidgets.QAction("Toggle history panel", self, checkable=True)
        toggle_history_action.setChecked(True)
        toggle_history_action.triggered.connect(self.toggle_history_visibility)
        view_menu.addAction(toggle_history_action)

        # Help
        help_menu = menubar.addMenu("&Help")
        about_action = QtWidgets.QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    # ---------- STYLES ----------

    def _apply_global_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #202124;
            }
            QGroupBox {
                color: #ffffff;
                font-weight: 600;
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 4px;
            }
            QLabel {
                color: #e8eaed;
            }
            QLineEdit, QPlainTextEdit {
                background-color: #303134;
                color: #e8eaed;
                border-radius: 4px;
                padding: 4px;
                border: 1px solid #555;
            }
            QSpinBox, QSlider, QCheckBox, QMenuBar, QMenu, QStatusBar {
                color: #e8eaed;
                background-color: #202124;
            }
            QSpinBox, QSlider {
                border: none;
            }
            QPushButton {
                background-color: #1a73e8;
                color: #ffffff;
                border-radius: 4px;
                padding: 6px 12px;
                border: 1px solid #1a73e8;
            }
            QPushButton:hover {
                background-color: #4285f4;
            }
            QPushButton:pressed {
                background-color: #3367d6;
            }
            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                background-color: #303134;
                color: #e8eaed;
            }
            QProgressBar::chunk {
                border-radius: 4px;
                margin: 0px;
            }
            """
        )

    def _set_strength_bar_style(self, strength: str) -> None:
        """
        Set color of the progress bar chunk based on strength classification.
        """
        color = "#d32f2f"  # default red
        if strength == "Weak":
            color = "#f57c00"  # orange
        elif strength == "Reasonable":
            color = "#fbc02d"  # yellow
        elif strength == "Strong":
            color = "#388e3c"  # green
        elif strength == "Very strong":
            color = "#2e7d32"  # darker green

        self.strength_bar.setStyleSheet(
            f"""
            QProgressBar {{
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                background-color: #303134;
                color: #e8eaed;
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
                margin: 0px;
                background-color: {color};
            }}
            """
        )

    # ---------- SETTINGS ----------

    def _load_settings(self) -> None:
        self.length_spin.setValue(self.settings.value("length", 16, type=int))
        self.batch_spin.setValue(self.settings.value("batch", 1, type=int))

        self.lower_cb.setChecked(self.settings.value("lower", True, type=bool))
        self.upper_cb.setChecked(self.settings.value("upper", True, type=bool))
        self.digits_cb.setChecked(self.settings.value("digits", True, type=bool))
        self.symbols_cb.setChecked(self.settings.value("symbols", True, type=bool))

        self.exclude_similar_cb.setChecked(
            self.settings.value("exclude_similar", False, type=bool)
        )
        self.no_repeat_cb.setChecked(
            self.settings.value("no_repeat", False, type=bool)
        )
        self.custom_chars_edit.setText(
            self.settings.value("custom_chars", "", type=str)
        )

    def _save_settings(self) -> None:
        self.settings.setValue("length", self.length_spin.value())
        self.settings.setValue("batch", self.batch_spin.value())

        self.settings.setValue("lower", self.lower_cb.isChecked())
        self.settings.setValue("upper", self.upper_cb.isChecked())
        self.settings.setValue("digits", self.digits_cb.isChecked())
        self.settings.setValue("symbols", self.symbols_cb.isChecked())

        self.settings.setValue("exclude_similar", self.exclude_similar_cb.isChecked())
        self.settings.setValue("no_repeat", self.no_repeat_cb.isChecked())
        self.settings.setValue("custom_chars", self.custom_chars_edit.text())

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self._save_settings()
        super().closeEvent(event)

    # ---------- CHARACTER SET BUILDING ----------

    def _build_char_sets(self) -> Tuple[List[str], str]:
        similar_chars = set("0Ool1I5S2Z6G8B")

        def filter_chars(chars: str, exclude_similar: bool) -> str:
            if not exclude_similar:
                return "".join(sorted(set(chars)))
            return "".join(sorted({c for c in chars if c not in similar_chars}))

        exclude_similar = self.exclude_similar_cb.isChecked()
        groups: List[str] = []

        if self.lower_cb.isChecked():
            g = filter_chars(string.ascii_lowercase, exclude_similar)
            if g:
                groups.append(g)
        if self.upper_cb.isChecked():
            g = filter_chars(string.ascii_uppercase, exclude_similar)
            if g:
                groups.append(g)
        if self.digits_cb.isChecked():
            g = filter_chars(string.digits, exclude_similar)
            if g:
                groups.append(g)
        if self.symbols_cb.isChecked():
            base_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
            g = filter_chars(base_symbols, exclude_similar)
            if g:
                groups.append(g)

        custom = self.custom_chars_edit.text()
        if custom:
            g = filter_chars(custom, exclude_similar=False)
            if g:
                groups.append(g)

        full_alphabet = "".join(sorted(set("".join(groups))))
        return groups, full_alphabet

    # ---------- LIVE PREVIEW ----------

    def update_live_preview(self) -> None:
        length = self.length_spin.value()
        groups, full_alphabet = self._build_char_sets()
        alphabet_size = len(set(full_alphabet))

        if not full_alphabet:
            self.live_entropy_label.setText(
                "Live entropy preview: no characters selected."
            )
            self.strength_bar.setValue(0)
            self.strength_label.setText("Strength: N/A")
            return

        entropy_bits = self.core.estimate_entropy(length, alphabet_size)
        strength = self.core.classify_strength(entropy_bits)
        brute = self.core.format_bruteforce_time(entropy_bits)

        self.live_entropy_label.setText(
            f"Alphabet size: {alphabet_size} | Estimated entropy: {entropy_bits:.2f} bits ({strength})"
        )

        # Update strength bar (cap at 128 bits for visualization)
        value = int(min(max(entropy_bits, 0.0), 128.0))
        self.strength_bar.setValue(value)
        self.strength_label.setText(f"Strength: {strength}")
        self._set_strength_bar_style(strength)

        # Also update detailed metrics (pre-generation preview)
        self.metrics_label.setText(
            f"Preview:\n"
            f" - Length: {length}\n"
            f" - Alphabet size: {alphabet_size}\n"
            f" - Entropy: {entropy_bits:.2f} bits ({strength})\n"
            f" - Estimated brute-force time: {brute}"
        )

    # ---------- ACTIONS ----------

    def on_generate_clicked(self) -> None:
        length = self.length_spin.value()
        batch = self.batch_spin.value()

        groups, full_alphabet = self._build_char_sets()

        if not full_alphabet:
            QtWidgets.QMessageBox.warning(
                self,
                "No characters selected",
                "Please select at least one character group or provide custom characters.",
            )
            return

        if len(groups) > length:
            QtWidgets.QMessageBox.warning(
                self,
                "Length too short",
                "Password length is too short to guarantee at least one character\n"
                "from each selected group. Increase length or deselect groups.",
            )
            return

        avoid_repeats = self.no_repeat_cb.isChecked()

        generated: List[str] = []

        try:
            for _ in range(batch):
                pwd = self.core.generate_unique_password(
                    length=length,
                    group_char_sets=groups,
                    full_alphabet=full_alphabet,
                    avoid_repeats=avoid_repeats,
                )
                generated.append(pwd)
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self,
                "Generation error",
                f"Password generation failed:\n{e}",
            )
            return

        # Show last password in main field
        last_password = generated[-1]
        self.password_edit.setText(last_password)

        # Append all generated to history panel
        history_current = self.history_edit.toPlainText().strip()
        block = "\n".join(generated)
        if history_current:
            self.history_edit.setPlainText(history_current + "\n" + block)
        else:
            self.history_edit.setPlainText(block)

        # Update metrics (same across batch, so just reuse live preview)
        groups, full_alphabet = self._build_char_sets()
        alphabet_size = len(set(full_alphabet))
        entropy_bits = self.core.estimate_entropy(length, alphabet_size)
        strength = self.core.classify_strength(entropy_bits)
        brute = self.core.format_bruteforce_time(entropy_bits)

        self.metrics_label.setText(
            f"Generated {batch} unique password(s).\n"
            f"Length: {length} characters\n"
            f"Alphabet size: {alphabet_size} unique characters\n"
            f"Estimated entropy: {entropy_bits:.2f} bits ({strength})\n"
            f"Approximate brute-force time: {brute}"
        )

        self.status_bar.showMessage(f"Generated {batch} unique password(s).", 8000)

    def on_copy_clicked(self) -> None:
        pwd = self.password_edit.text()
        if not pwd:
            self.status_bar.showMessage("No password to copy.", 5000)
            return
        QtWidgets.QApplication.clipboard().setText(pwd)
        self.status_bar.showMessage("Password copied to clipboard.", 5000)

    def on_clear_clicked(self) -> None:
        self.password_edit.clear()
        self.status_bar.showMessage("Output cleared.", 5000)

    def toggle_history_visibility(self, checked: bool) -> None:
        self.centralWidget().layout().itemAt(1).widget().setVisible(checked)

    def show_about_dialog(self) -> None:
        QtWidgets.QMessageBox.information(
            self,
            "About Ultra Secure Unique Password Generator Pro",
            (
                "Ultra Secure Unique Password Generator Pro\n\n"
                "• Cryptographically secure randomness (secrets.SystemRandom)\n"
                "• Global uniqueness via SHA-256 hash history in your home directory\n"
                "• Live entropy preview and brute-force time estimates\n"
                "• Professional dark-themed interface with batch generation\n\n"
                "Recommendation: store generated passwords in a reputable password manager."
            ),
        )


# =========================
#          ENTRY
# =========================

def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Ultra Secure Unique Password Generator Pro")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
