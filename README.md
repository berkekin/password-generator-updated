# password-generator-updated

# Ultra Secure Unique Password Generator Pro

A professional, cross-platform desktop application for generating **cryptographically secure**, **never-repeated** passwords with a **modern graphical interface** and **transparent security math**.

Built with **Python** and **PyQt5**.

---


---

## Overview

This application is designed for users who want **serious**, **repeatable**, and **transparent** password generation standards:

- It uses **cryptographically secure randomness** (`secrets.SystemRandom`).
- It enforces **global uniqueness**: once a password is generated, the same password will **never** be generated again by this application (as long as the history file is preserved).
- It offers a **professional GUI** with:
  - Dark theme
  - Toolbar, menus, status bar
  - Live entropy preview
  - Strength bar
  - Batch generation
  - Session history

The program does *not* send any data over the network. All operations happen locally on the user’s machine.

---

## Key Features

### 1. Cryptographically Secure Password Generation

- Uses Python’s `secrets.SystemRandom` for high-quality, cryptographic random numbers.
- Passwords are uniformly generated from a well-defined character alphabet.
- Each generated password is built using:
  - At least one character from each **selected** character group.
  - Optional constraints (no repeated characters, excluding similar characters).

### 2. Global Uniqueness Guarantee

- After generating a password, the app stores its **SHA-256 hash** in a history file.
- On subsequent generations, it checks the new password’s hash against this history.
- If the hash already exists, the password is discarded and a new one is generated.
- Practically, this means **the same password will never be produced twice** by this application instance (as long as the history file exists and remains intact).

### 3. Professional Graphical User Interface (PyQt5)

- Dark, modern theme with carefully chosen colors.
- **Toolbar** with quick actions:
  - Generate
  - Copy
  - Clear
  - About
- **Menu bar**:
  - File → Exit
  - View → Toggle history panel
  - Help → About
- **Status bar** showing contextual messages (ready, errors, actions).

### 4. Live Entropy and Strength Preview

- As you adjust settings (length, character sets, options), the app shows:
  - Alphabet size
  - Estimated entropy (in bits)
  - Strength classification (Very weak / Weak / Reasonable / Strong / Very strong)
  - Estimated brute-force time at \(10^{10}\) guesses per second
- Strength is also visualized with a **color-coded progress bar**.

### 5. Batch Generation

- You can generate **multiple unique passwords at once**:
  - Choose how many passwords to generate (1–100).
  - All are guaranteed unique (against previous passwords and each other).
  - All batch results are shown in the session history panel.

### 6. Session History Panel

- A lower panel lists all passwords generated during the current run of the application.
- This panel can be shown or hidden via the **View → Toggle history panel** menu.
- Note: This is in-memory for the session; it is not stored on disk.

### 7. Settings Persistence

- The app uses `QSettings` to remember your preferences:
  - Password length
  - Batch size
  - Which character sets are enabled
  - Whether to exclude similar characters
  - Whether to avoid repeated characters
  - Custom characters
- On next launch, your last configuration is automatically restored.

---

## Security Model & Uniqueness

### History File

- By default, the application writes the password hash history to:

  ```text
  ~/.unique_password_hashes.txt
