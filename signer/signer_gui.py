import gzip
import json
import os
import sys
import hashlib

from signer.version import __version__

import qrcode

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QCheckBox,
    QMessageBox,
    QInputDialog,
    QComboBox,
    QPlainTextEdit,
    QScrollArea,
    QStyle,
    QTextBrowser,
)

from signer.wallet_storage import (
    create_wallet_metadata,
    save_metadata,
    save_active_secret,
    load_active_metadata,
    load_active_secret,
    wallet_name_exists,
    get_archive_directory,
    archive_active_wallet,
    load_archived_wallet,
    delete_active_wallet,
    delete_archived_wallet,
)


from bitcoinx import (
    BIP32PrivateKey,
    bip32_key_from_string,
    P2MultiSig_Output,
)

from electrumsv.bip276 import (
    bip276_encode,
    PREFIX_BIP276_SCRIPT,
)

from electrumsv import bitcoin
from electrumsv.bitcoin import base_encode, bh2u
from electrumsv.keystore import (
    bip39_is_checksum_valid,
    bip39_to_seed,
)
from electrumsv.networks import Net
from electrumsv.qrscanner import scan_barcode
from electrumsv.qrtransport import create_frames
from electrumsv.transaction import (
    Transaction,
    tx_output_to_display_text,
    txdict_from_str,
)

from signer.seed_generator import generate_recovery_phrase
from signer.signer_protocol import apply_signing_response, create_signing_request
from signer.transaction_signer import sign_approved_transaction, transaction_fingerprint
IS_LINUX = sys.platform.startswith("linux")


if IS_LINUX:
    from signer.luks_manager import (
        close_storage,
        find_filesystem_device,
        find_mount_path,
        find_removable_storage_devices,
        open_storage,
        ensure_storage_layout,
        get_storage_label,
        initialize_luks_device,
    )

from electrumsv.gui.qt.theme import DARK_THEME


DEFAULT_ACCOUNT_DERIVATION = "m/44'/0'/0'"


def resource_path(filename):
    """Return the path to a Signer resource."""

    if getattr(
        sys,
        "_MEIPASS",
        None,
    ):
        return os.path.join(
            sys._MEIPASS,
            "signer",
            filename,
        )

    return os.path.join(
        os.path.dirname(__file__),
        filename,
    )


class SignerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            f"ElectrumSVP Signer {__version__}"
        )
        self.setMinimumSize(500, 500)
        self.layout = QVBoxLayout(self)

        self.session_mnemonic = None
        self.session_is_persistent = False
        self.storage_mount_path = None
        self.active_wallet_id = None
        self.active_wallet_name = None

        self.show_home()

        self.center_window()

    def center_window(self):
        """Center the window on the primary screen."""

        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()

        self.setGeometry(
            QStyle.alignedRect(
                Qt.LeftToRight,
                Qt.AlignCenter,
                self.size(),
                screen_geometry,
            )
        )

    # ------------------------------------------------------------------
    # General helpers
    # ------------------------------------------------------------------

    def clear_layout(self):
        """Remove the current screen and all of its widgets."""
        if getattr(self, "signing_qr_timer", None) is not None:
            self.signing_qr_timer.stop()
            self.signing_qr_timer.deleteLater()
            self.signing_qr_timer = None

        def clear_layout_items(layout):
            while layout.count():
                item = layout.takeAt(0)

                widget = item.widget()
                if widget is not None:
                    widget.clearFocus()
                    widget.hide()
                    widget.setParent(None)
                    widget.deleteLater()
                    continue

                child_layout = item.layout()
                if child_layout is not None:
                    clear_layout_items(child_layout)

        clear_layout_items(self.layout)


    def clear_child_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()

            if widget is not None:
                widget.clearFocus()
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()

            if child_layout is not None:
                self.clear_child_layout(child_layout)

    def copy_text(self, text):
        QApplication.clipboard().setText(text)

    def save_signed_transaction(self, signed_transaction_json):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Signed Transaction",
            "signed_transaction.json",
            "Transaction Files (*.json *.txt);;All Files (*)",
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(signed_transaction_json)

            QMessageBox.information(
                self,
                "Transaction Saved",
                f"The signed transaction was saved to:\n\n{file_path}",
            )
        except Exception as e:
            self.show_error(
                f"Unable to save the signed transaction:\n\n{e}"
            )



    def confirm_session_only_wallet(self, mnemonic):
        """Confirm that the wallet will remain session-only."""

        self.session_mnemonic = mnemonic
        self.session_is_persistent = False
        self.active_wallet_id = None
        self.active_wallet_name = None

        if IS_LINUX:
            try:
                close_storage()
            except Exception as e:
                self.update_storage_state()
                self.show_error(
                    f"Unable to lock wallet storage:\n\n{e}"
                )
                return

        self.storage_mount_path = None

        message = QMessageBox(self)
        message.setWindowTitle("Session-Only Wallet")
        message.setIcon(QMessageBox.Information)
        message.setText(
            "This wallet will be used only for the current session."
        )
        message.setInformativeText(
            "The recovery phrase will not be saved to encrypted "
            "storage.\n\n"
            "The encrypted wallet storage has been locked. "
            "The recovery phrase will remain available in memory "
            "for the current signing session."
        )
        message.setStandardButtons(QMessageBox.Ok)

        message.exec_()

        self.show_signer_ready(mnemonic)



    def show_initialize_storage(self):
        """Show removable USB devices available for initialization."""

        devices = find_removable_storage_devices()

        self.clear_layout()
        self.resize(600, 500)

        title = QLabel(
            "Initialize New Wallet Storage"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Select a removable USB device to initialize as "
            "encrypted wallet storage."
        )
        instructions.setWordWrap(True)

        device_combo = QComboBox()

        for device in devices:
            device_combo.addItem(
                f"{device['name']} — {device['size']} "
                f"({device['path']})",
                device["path"],
            )

        continue_button = QPushButton(
            "Continue"
        )
        continue_button.setMinimumHeight(42)
        continue_button.clicked.connect(
            lambda: self.show_initialize_confirmation(
                device_combo.currentData()
            )
        )


        cancel_button = QPushButton(
            "Cancel"
        )
        cancel_button.setMinimumHeight(42)
        cancel_button.clicked.connect(
            self.show_home
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(15)

        if devices:
            self.layout.addWidget(device_combo)
            self.layout.addSpacing(15)
            self.layout.addWidget(continue_button)
        else:
            no_devices = QLabel(
                "No removable USB storage devices were found."
            )
            no_devices.setWordWrap(True)
            self.layout.addWidget(no_devices)

        self.layout.addWidget(cancel_button)
        self.layout.addStretch()



    def show_storage_name(self, device_path):
        """Ask the user to choose a name for the encrypted storage."""

        self.clear_layout()
        self.resize(600, 500)

        title = QLabel(
            "Name Your Wallet Storage"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Choose a name for this encrypted wallet storage. "
            "This name will be used to identify the storage device "
            "inside ElectrumSVP Signer."
        )
        instructions.setWordWrap(True)

        name_input = QLineEdit()
        name_input.setPlaceholderText(
            "For example: ElectrumSVP Wallet"
        )
        name_input.setMinimumHeight(40)

        continue_button = QPushButton(
            "Continue"
        )
        continue_button.setMinimumHeight(42)
        continue_button.clicked.connect(
            lambda: self.show_storage_passphrase(
                device_path,
                name_input.text(),
            )
        )

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(42)
        back_button.clicked.connect(
            lambda: self.show_initialize_confirmation(
                device_path
            )
        )

        self.layout.addStretch()
        self.layout.addWidget(
            title
        )
        self.layout.addSpacing(15)
        self.layout.addWidget(
            instructions
        )
        self.layout.addSpacing(20)
        self.layout.addWidget(
            QLabel("Storage name:")
        )
        self.layout.addWidget(
            name_input
        )
        self.layout.addSpacing(20)
        self.layout.addWidget(
            continue_button
        )
        self.layout.addWidget(
            back_button
        )
        self.layout.addStretch()

        name_input.setFocus()



    def show_storage_passphrase(
        self,
        device_path,
        storage_name,
    ):
        """Collect the LUKS passphrase for new wallet storage."""

        storage_name = storage_name.strip()

        if not storage_name:
            self.show_error(
                "Please enter a name for the wallet storage."
            )
            return

        self.clear_layout()
        self.resize(600, 550)

        title = QLabel(
            "Set Storage Passphrase"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Create a passphrase for the encrypted wallet storage.\n\n"
            "This passphrase protects the entire storage device. "
            "It is separate from your wallet recovery seed."
        )
        instructions.setWordWrap(True)

        name_label = QLabel(
            f"<b>Storage name:</b> {storage_name}"
        )
        name_label.setWordWrap(True)

        passphrase_input = QLineEdit()
        passphrase_input.setEchoMode(
            QLineEdit.Password
        )
        passphrase_input.setPlaceholderText(
            "Enter storage passphrase"
        )
        passphrase_input.setMinimumHeight(40)

        confirm_input = QLineEdit()
        confirm_input.setEchoMode(
            QLineEdit.Password
        )
        confirm_input.setPlaceholderText(
            "Confirm storage passphrase"
        )
        confirm_input.setMinimumHeight(40)

        continue_button = QPushButton(
            "Continue"
        )
        continue_button.setMinimumHeight(42)

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(42)
        back_button.clicked.connect(
            lambda: self.show_storage_name(
                device_path
            )
        )

        def continue_passphrase():
            passphrase = passphrase_input.text()
            confirmation = confirm_input.text()

            if not passphrase:
                self.show_error(
                    "Please enter a storage passphrase."
                )
                return

            if passphrase != confirmation:
                self.show_error(
                    "The passphrases do not match."
                )
                return

            self.show_initialize_final_confirmation(
                device_path,
                storage_name,
                passphrase,
            )

        continue_button.clicked.connect(
            continue_passphrase
        )

        self.layout.addStretch()

        self.layout.addWidget(
            title
        )

        self.layout.addSpacing(15)

        self.layout.addWidget(
            instructions
        )

        self.layout.addSpacing(15)

        self.layout.addWidget(
            name_label
        )

        self.layout.addSpacing(15)

        self.layout.addWidget(
            QLabel("Storage passphrase:")
        )

        self.layout.addWidget(
            passphrase_input
        )

        self.layout.addSpacing(10)

        self.layout.addWidget(
            QLabel("Confirm passphrase:")
        )

        self.layout.addWidget(
            confirm_input
        )

        self.layout.addSpacing(20)

        self.layout.addWidget(
            continue_button
        )

        self.layout.addWidget(
            back_button
        )

        self.layout.addStretch()

        passphrase_input.setFocus()



    def show_initialize_final_confirmation(
        self,
        device_path,
        storage_name,
        passphrase,
    ):
        """Show the final confirmation before initializing the USB device."""

        device = None

        for item in find_removable_storage_devices():
            if item["path"] == device_path:
                device = item
                break

        if device is None:
            self.show_error(
                "The selected USB device is no longer available."
            )
            return

        self.clear_layout()
        self.resize(600, 650)

        title = QLabel(
            "Final Confirmation"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: ALL DATA ON THIS DEVICE WILL BE "
            "PERMANENTLY ERASED."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 14px; font-weight: bold;"
        )

        device_info = QLabel(
            f"<b>Device:</b> {device['path']}<br>"
            f"<b>Size:</b> {device['size']}<br>"
            f"<b>Transport:</b> USB<br>"
            f"<b>Storage name:</b> {storage_name}"
        )
        device_info.setWordWrap(True)

        explanation = QLabel(
            "The USB device will be initialized as LUKS-encrypted "
            "wallet storage for ElectrumSVP Signer.\n\n"
            "The storage passphrase protects the encrypted device. "
            "If you lose the passphrase, the encrypted storage "
            "cannot be unlocked by ElectrumSVP Signer."
        )
        explanation.setWordWrap(True)

        initialize_button = QPushButton(
            "Initialize Device"
        )
        initialize_button.setMinimumHeight(42)

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(42)
        back_button.clicked.connect(
            lambda: self.show_storage_passphrase(
                device_path,
                storage_name,
            )
        )

        initialize_button.clicked.connect(
            lambda: self.initialize_storage(
                device_path,
                storage_name,
                passphrase,
            )
        )

        self.layout.addStretch()

        self.layout.addWidget(
            title
        )

        self.layout.addSpacing(15)

        self.layout.addWidget(
            warning
        )

        self.layout.addSpacing(20)

        self.layout.addWidget(
            device_info
        )

        self.layout.addSpacing(20)

        self.layout.addWidget(
            explanation
        )

        self.layout.addSpacing(25)

        self.layout.addWidget(
            initialize_button
        )

        self.layout.addWidget(
            back_button
        )

        self.layout.addStretch()




    def show_initialize_confirmation(self, device_path):
        """Show the destructive-operation warning for USB initialization."""

        device = None

        for item in find_removable_storage_devices():
            if item["path"] == device_path:
                device = item
                break

        if device is None:
            self.show_error(
                "The selected USB device is no longer available."
            )
            return

        self.clear_layout()
        self.resize(600, 550)

        title = QLabel(
            "Initialize Encrypted Wallet Storage"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: ALL DATA ON THIS USB DEVICE WILL BE "
            "PERMANENTLY ERASED.\n\n"
            "This includes existing files, partitions, and "
            "filesystems on the device."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 14px; font-weight: bold;"
        )

        device_info = QLabel(
            f"<b>Device:</b> {device['path']}<br>"
            f"<b>Size:</b> {device['size']}<br>"
            f"<b>Transport:</b> USB"
        )
        device_info.setWordWrap(True)

        explanation = QLabel(
            "The device will eventually be initialized as a "
            "LUKS-encrypted wallet storage device. "
            "No changes have been made yet."
        )
        explanation.setWordWrap(True)

        continue_button = QPushButton(
            "Continue"
        )
        continue_button.setMinimumHeight(42)
        continue_button.clicked.connect(
            lambda: self.show_storage_name(
                device_path
            )
        )

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(42)
        back_button.clicked.connect(
            self.show_initialize_storage
        )

        self.layout.addStretch()

        self.layout.addWidget(
            title
        )

        self.layout.addSpacing(15)

        self.layout.addWidget(
            warning
        )

        self.layout.addSpacing(20)

        self.layout.addWidget(
            device_info
        )

        self.layout.addSpacing(20)

        self.layout.addWidget(
            explanation
        )

        self.layout.addSpacing(25)

        self.layout.addWidget(
            continue_button
        )

        self.layout.addWidget(
            back_button
        )

        self.layout.addStretch()



    def initialize_storage(
        self,
        device_path,
        storage_name,
        passphrase,
    ):
        """Initialize the selected USB as encrypted wallet storage."""

        try:
            initialize_luks_device(
                device_path,
                storage_name,
                passphrase,
            )

        except Exception as e:
            self.show_error(
                f"Unable to initialize the wallet storage:\n\n{e}"
            )
            return

        self.show_error(
            "Wallet storage was initialized successfully."
        )





    def show_signer_ready_from_session(self):
        """Show wallet management for the active signing session."""

        if self.session_mnemonic is None:
            self.show_error(
                "No signing session is currently active."
            )
            return

        self.show_signer_ready(self.session_mnemonic)



    def show_recovery_seed_warning(self, mnemonic):
        self.clear_layout()
        title = QLabel("Recovery Seed")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        warning = QLabel(
            "WARNING: THIS RECOVERY SEED IS HIGHLY SENSITIVE.\n\n"
            "Anyone who obtains the recovery seed can recover the wallet "
            "and spend its funds.\n\n"
            "Only reveal or copy this recovery seed when you understand "
            "exactly why it is needed."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        reveal = QPushButton(
            "Reveal Recovery Seed"
        )
        reveal.setMinimumHeight(42)
        reveal.clicked.connect(
            lambda: self.show_recovery_seed(mnemonic)
        )

        cancel = QPushButton(
            "Cancel"
        )
        cancel.setMinimumHeight(42)
        cancel.clicked.connect(
            lambda: self.show_signer_ready(mnemonic)
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(25)
        self.layout.addWidget(reveal)
        self.layout.addWidget(cancel)
        self.layout.addStretch()



    def show_recovery_seed(self, mnemonic):
        self.clear_layout()
        self.resize(650, 600)

        title = QLabel(
            "Recovery Seed"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: Anyone with this recovery seed can recover "
            "the wallet and spend its funds.\n\n"
            "Keep this seed offline and secure. Clear the clipboard "
            "after copying it."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        seed_display = QPlainTextEdit()
        seed_display.setReadOnly(True)
        seed_display.setPlainText(mnemonic)
        seed_display.setMinimumHeight(100)

        copy = QPushButton(
            "Copy Recovery Seed"
        )
        copy.setMinimumHeight(40)
        copy.clicked.connect(
            lambda: self.copy_text(mnemonic)
        )

        save = QPushButton(
            "Save Recovery Seed to File"
        )
        save.setMinimumHeight(40)

        def save_seed():
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Recovery Seed",
                "electrumsvp-recovery-seed.txt",
                "Text Files (*.txt);;All Files (*)",
            )

            if not path:
                return

            try:
                with open(
                    path,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(mnemonic)
            except Exception as e:
                self.show_error(
                    f"Unable to save the recovery seed:\n\n{e}"
                )
                return

            QMessageBox.information(
                self,
                "Recovery Seed Saved",
                "The recovery seed was saved to:\n\n"
                f"{path}\n\n"
                "Keep this file offline and secure. "
                "Anyone with the file can recover the wallet.",
            )

        save.clicked.connect(
            save_seed
        )

        back = QPushButton(
            "Back"
        )
        back.setMinimumHeight(40)
        back.clicked.connect(
            lambda: self.show_signer_ready(mnemonic)
        )

        self.layout.addWidget(
            title
        )
        self.layout.addSpacing(15)
        self.layout.addWidget(
            warning
        )
        self.layout.addSpacing(15)
        self.layout.addWidget(
            seed_display
        )
        self.layout.addSpacing(15)
        self.layout.addWidget(
            copy
        )
        self.layout.addWidget(
            save
        )
        self.layout.addWidget(
            back
        )
        self.layout.addStretch()




    def save_wallet_to_storage(self, mnemonic):
        """Save the current wallet to encrypted storage."""

        if self.storage_mount_path is None:
            self.show_error(
                "Encrypted wallet storage is not unlocked.\n\n"
                "Unlock the wallet storage before saving this wallet."
            )
            return

        wallet_name, ok = QInputDialog.getText(
            self,
            "Save Wallet",
            "Enter a name for this wallet:",
        )

        if not ok:
            return

        wallet_name = wallet_name.strip()

        if not wallet_name:
            self.show_error(
                "Wallet name cannot be empty."
            )
            return

        if wallet_name_exists(wallet_name):
            self.show_error(
                "A wallet with this name already exists.\n\n"
                "Please choose a different wallet name."
            )
            return

        try:
            metadata = create_wallet_metadata(wallet_name)

            archive_active_wallet()

            save_metadata(metadata)
            save_active_secret(mnemonic)

            self.active_wallet_id = metadata["wallet_id"]
            self.active_wallet_name = metadata["wallet_name"]
            self.session_is_persistent = True

        except Exception as e:

            self.show_error(
                f"Unable to save wallet to encrypted storage:\n\n{e}"
            )
            return

        self.session_mnemonic = mnemonic

        QMessageBox.information(
            self,
            "Wallet Saved",
            "The wallet has been saved to encrypted storage.\n\n"
            f"Wallet name: {wallet_name}\n\n"
            "The recovery phrase remains available for the current "
            "signing session.",
        )

        self.show_signer_ready(mnemonic)



    def load_selected_wallet(self, wallet_id):
        """Load an archived wallet as the active wallet."""

        if not wallet_id:
            self.show_error(
                "Please select an archived wallet first."
            )
            return

        try:
            metadata, mnemonic = load_archived_wallet(
                wallet_id
            )

        except Exception as e:
            self.show_error(
                f"Unable to load wallet:\n\n{e}"
            )
            return

        self.session_mnemonic = mnemonic
        self.session_is_persistent = True
        self.active_wallet_id = metadata["wallet_id"]
        self.active_wallet_name = metadata["wallet_name"]

        self.show_signer_ready(mnemonic)



    def delete_selected_wallet(self, wallet_id):
        """Delete a selected archived wallet."""

        if not wallet_id:
            self.show_error(
                "Please select an archived wallet first."
            )
            return

        archive_directory = get_archive_directory()

        metadata_path = os.path.join(
            archive_directory,
            wallet_id,
            "wallet.json",
        )

        if not os.path.isfile(metadata_path):
            self.show_error(
                "The selected wallet could not be found."
            )
            return

        try:
            with open(
                metadata_path,
                "r",
                encoding="utf-8",
            ) as file:
                metadata = json.load(file)

            wallet_name = metadata.get(
                "wallet_name",
                "",
            ).strip()

        except Exception as e:
            self.show_error(
                f"Unable to read the selected wallet:\n\n{e}"
            )
            return

        if not wallet_name:
            wallet_name = "this wallet"

        confirmation = QMessageBox.question(
            self,
            "Delete Wallet",
            (
                f"Are you sure you want to permanently delete "
                f"the archived wallet '{wallet_name}'?\n\n"
                "This will delete its stored recovery seed and "
                "wallet metadata from encrypted storage.\n\n"
                "This action cannot be undone."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if confirmation != QMessageBox.Yes:
            return

        try:
            delete_archived_wallet(wallet_id)

        except Exception as e:
            self.show_error(
                f"Unable to delete the wallet:\n\n{e}"
            )
            return


        index = self.archive_combo.findData(
            wallet_id
        )

        if index >= 0:
            self.archive_combo.removeItem(
                index
        )

        QMessageBox.information(
            self,
            "Wallet Deleted",
            f"Wallet '{wallet_name}' was deleted.",
        )


    def clear_session(self):
        """Clear the active session and lock encrypted wallet storage."""

        self.session_mnemonic = None

        if IS_LINUX:
            try:
                close_storage()
            except Exception as e:
                self.update_storage_state()
                self.show_error(
                    f"Unable to lock wallet storage:\n\n{e}"
                )
                return

        self.storage_mount_path = None
        self.show_home()


    def import_recovery_phrase(self, phrase):
        """Validate and load an existing BIP39 recovery phrase."""

        phrase = " ".join(phrase.strip().split())

        if not phrase:
            self.show_error(
                "No recovery phrase was entered."
            )
            return

        word_count = len(phrase.split())

        if word_count not in (12, 24):
            self.show_error(
                "Recovery phrase must contain 12 or 24 words."
            )
            return

        is_valid, is_checksum_valid = bip39_is_checksum_valid(
            phrase
        )

        if not is_valid or not is_checksum_valid:
            self.show_error(
                "The recovery phrase is not a valid BIP39 phrase."
            )
            return

        self.session_mnemonic = phrase
        self.session_is_persistent = False
        self.show_signer_ready(phrase)

    def update_storage_state(self):
        """Refresh the GUI's view of encrypted wallet storage."""

        if not IS_LINUX:
            self.storage_mount_path = None
            return

        device = find_filesystem_device()

        if device is None:
            self.storage_mount_path = None
            return

        self.storage_mount_path = find_mount_path(device)


    def unlock_storage(self):
        """Prompt for the storage password, then unlock and mount storage."""
        password, ok = QInputDialog.getText(
            self,
            "Unlock Wallet Storage",
            "Enter wallet storage passphrase:",
            QLineEdit.Password,
        )

        if not ok:
            return

        if not password:
            self.show_error("A passphrase is required to unlock wallet storage.")
            return

        try:
            mount_path = open_storage(password)
            ensure_storage_layout()
            active_metadata = load_active_metadata()
            active_mnemonic = load_active_secret()

            if active_metadata is not None and active_mnemonic:
                self.session_mnemonic = active_mnemonic
                self.session_is_persistent = True
                self.active_wallet_id = active_metadata["wallet_id"]
                self.active_wallet_name = active_metadata["wallet_name"]

        except Exception as e:

            try:
                close_storage()
            except Exception:
                pass

            self.update_storage_state()
            self.show_error(f"Unable to unlock wallet storage:\n\n{e}")
            return

        self.storage_mount_path = mount_path
        self.show_home()


    def lock_storage(self):
        """Clear the active session, then unmount and lock wallet storage."""

        self.session_mnemonic = None
        self.active_wallet_id = None
        self.active_wallet_name = None

        if IS_LINUX:
            try:
                close_storage()
            except Exception as e:
                self.update_storage_state()
                self.show_error(
                    f"Unable to lock wallet storage:\n\n{e}"
                )
                return

        self.storage_mount_path = None
        self.session_is_persistent = False

        self.show_home()


    def exit_application(self):
        """Clear the session and lock wallet storage before exiting."""

        self.session_mnemonic = None
        self.active_wallet_id = None
        self.active_wallet_name = None

        if IS_LINUX:
            try:
                close_storage()
            except Exception as e:
                self.update_storage_state()
                self.show_error(
                    f"Unable to lock wallet storage:\n\n{e}"
                )
                return

        self.storage_mount_path = None
        self.session_is_persistent = False

        self.close()


    def closeEvent(self, event):
        """Lock wallet storage when the window is closed."""

        self.session_mnemonic = None
        self.active_wallet_id = None
        self.active_wallet_name = None

        if IS_LINUX:
            try:
                close_storage()
            except Exception as e:
                self.update_storage_state()
                self.show_error(
                    f"Unable to lock wallet storage:\n\n{e}"
                )
                event.ignore()
                return

        self.storage_mount_path = None
        self.session_is_persistent = False

        event.accept()


    def save_text_to_file(self, text, title, default_name):
        path, _ = QFileDialog.getSaveFileName(
            self,
            title,
            default_name,
            "Text Files (*.txt);;All Files (*)",
        )

        if not path:
            return False

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception as e:
            self.show_error(f"Unable to save the file:\n\n{e}")
            return False

        return True

    def parse_derivation_path(self, path):
        """Parse strict m/0'/1 notation into BIP32 integer indexes."""
        path = path.strip()
        if not path:
            raise ValueError("Derivation path cannot be empty.")
        if path == "m":
            return ()
        if not path.startswith("m/"):
            raise ValueError("Derivation path must start with m/.")

        result = []
        parts = path[2:].split("/")
        for part in parts:
            if not part:
                raise ValueError("Derivation path contains an empty component.")
            hardened = part.endswith("'")
            number = part[:-1] if hardened else part
            if not number.isdigit():
                raise ValueError(
                    f"Invalid derivation component: {part}\n\n"
                    "Use numbers with an optional trailing apostrophe."
                )
            index = int(number)
            if index >= 0x80000000:
                raise ValueError("Derivation index is too large.")
            if hardened:
                index |= 0x80000000
            result.append(index)
        return tuple(result)

    def derive_key_from_path(self, master_key, path):
        key = master_key
        for index in self.parse_derivation_path(path):
            key = key.child_safe(index)
        return key

    def derive_master_key(self, mnemonic):
        mnemonic = mnemonic.strip()

        seed = bip39_to_seed(
            mnemonic,
            None,
        )

        print()
        print("GUI DERIVATION DIAGNOSTICS")
        print("--------------------------")
        print(
            f"Mnemonic word count: "
            f"{len(mnemonic.split())}"
        )

        master_key = BIP32PrivateKey.from_seed(
            seed,
            Net.COIN,
        )

        print()

        return master_key


    def session_fingerprint(self):
        if not self.session_mnemonic:
            return None

        try:
            master_key = self.derive_master_key(self.session_mnemonic)
            fingerprint = master_key.fingerprint()
            return fingerprint.hex()
        except Exception:
            return None


    def add_session_status(self):
        if not self.session_mnemonic:
            return

        fingerprint = self.session_fingerprint()
        if not fingerprint:
            return

        if self.active_wallet_name is not None:
            wallet_text = self.active_wallet_name

            storage_label = get_storage_label()

            if storage_label:
                storage_text = storage_label
            else:
                storage_text = "Encrypted wallet storage"

        else:
            wallet_text = "Session-only"
            storage_text = "RAM only"


        status = QLabel(
            f"<b>Session Active</b><br>"
            f"Seed: {fingerprint}<br>"
            f"Wallet: {wallet_text}<br>"
            f"Storage: {storage_text}"
        )
        status.setStyleSheet(
            "font-size: 11px; font-weight: bold;"
        )

        button_layout = QHBoxLayout()

        wallet_button = QPushButton(
            "Wallet Status & Management"
        )
        wallet_button.setMinimumHeight(30)
        wallet_button.clicked.connect(
            self.show_signer_ready_from_session
        )

        clear_button = QPushButton(
            "Clear Session"
        )
        clear_button.setMinimumHeight(30)
        clear_button.clicked.connect(
            self.clear_session
        )

        button_layout.addWidget(wallet_button)
        button_layout.addWidget(clear_button)

        self.layout.addWidget(status)
        self.layout.addLayout(button_layout)
        self.layout.addSpacing(8)



    def key_to_xprv(self, key):
        return key.to_extended_key_string()

    def key_to_xpub(self, key):
        return key.public_key.to_extended_key_string()

    def private_key_wif(self, private_key):
        """Return compressed mainnet P2PKH WIF."""
        return private_key.to_WIF(
            compressed=True,
            network=Net.COIN,
        )

    def public_key_to_address(self, public_key):
        """Convert a bitcoinx public key to a legacy P2PKH address."""
        return public_key.to_address(network=Net.COIN).to_string()

    # ------------------------------------------------------------------
    # Home
    # ------------------------------------------------------------------


    def show_home(self):
        self.resize(560, 700)
        self.clear_layout()
        self.update_storage_state()
        self.add_session_status()

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)

        logo_path = resource_path(
            "electrumsvpsignerlogo.png"
        )

        pixmap = QPixmap(logo_path)

        if not pixmap.isNull():
            pixmap = pixmap.scaled(
                400,
                81,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            logo.setPixmap(pixmap)

        subtitle = QLabel("Offline Transaction Signer")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            "font-size: 14px;"
        )

        storage_widgets = []

        if IS_LINUX:
            storage_status = QLabel(
                "Wallet Storage: "
                + (
                    "Unlocked"
                    if self.storage_mount_path
                    else "Locked"
                )
            )
            storage_status.setStyleSheet(
                "font-size: 12px; font-weight: bold;"
            )

            if self.storage_mount_path:
                storage_button = QPushButton(
                    "Lock Wallet Storage"
                )
                storage_button.clicked.connect(
                    self.lock_storage
                )
            else:
                storage_button = QPushButton(
                    "Unlock Wallet Storage"
                )
                storage_button.clicked.connect(
                    self.unlock_storage
                )

            storage_button.setMinimumHeight(42)

            initialize_button = QPushButton(
                "Initialize New USB Storage"
            )
            initialize_button.setMinimumHeight(42)
            initialize_button.clicked.connect(
                self.show_initialize_storage
            )

            storage_widgets = [
                storage_status,
                storage_button,
                initialize_button,
            ]


        buttons = [
            ("Load Transaction", self.show_load_transaction),
            (
                "Create/Import Signing Seed Phrase",
                self.show_create_wallet,
            ),
            (
                "Address & Key Derivation",
                self.show_derivation_tool,
            ),
            (
                "Multi-Sig Derivation",
                self.show_multisig_derivation_tool,
            ),
            ("Exit", self.exit_application),
        ]


        self.layout.addSpacing(15)
        self.layout.addWidget(logo)
        self.layout.addSpacing(5)
        self.layout.addWidget(subtitle)
        self.layout.addSpacing(20)

        if IS_LINUX:
            for widget in storage_widgets:
                self.layout.addWidget(widget)

            self.layout.addSpacing(15)

        for text, callback in buttons:
            button = QPushButton(text)
            button.setMinimumHeight(42)
            button.clicked.connect(callback)
            self.layout.addWidget(button)

            if text == "Address & Key Derivation":
                self.layout.addSpacing(8)

        self.layout.addStretch()

    # ------------------------------------------------------------------
    # Seed creation
    # ------------------------------------------------------------------

    def show_create_wallet(self):
        self.clear_layout()

        title = QLabel("Create or Import Wallet")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        instructions = QLabel(
            "Create a new recovery phrase or import an existing BIP39 "
            "recovery phrase.\n\n"
            "Anyone who obtains a recovery phrase can control the wallet's funds.\n\n"
            "Never photograph a recovery phrase, copy it to an online device, "
            "or share it with anyone."
        )
        instructions.setWordWrap(True)

        create_title = QLabel("Create New Wallet")
        create_title.setStyleSheet(
            "font-size: 17px; font-weight: bold;"
        )

        b12 = QPushButton("Generate 12-Word Recovery Phrase")
        b12.setMinimumHeight(42)
        b12.clicked.connect(
            lambda: self.start_wallet_creation(12)
        )

        b24 = QPushButton("Generate 24-Word Recovery Phrase")
        b24.setMinimumHeight(42)
        b24.clicked.connect(
            lambda: self.start_wallet_creation(24)
        )

        import_button = QPushButton("Import Existing Recovery Phrase")
        import_button.setMinimumHeight(42)
        import_button.clicked.connect(
            self.show_import_wallet
        )

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(self.show_home)

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(25)
        self.layout.addWidget(create_title)
        self.layout.addWidget(b12)
        self.layout.addWidget(b24)
        self.layout.addSpacing(20)
        self.layout.addWidget(import_button)
        self.layout.addSpacing(15)
        self.layout.addWidget(back)
        self.layout.addStretch()


    def show_import_wallet(self):
        self.clear_layout()
        self.resize(600, 500)

        title = QLabel("Import Recovery Phrase")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Enter an existing BIP39 recovery phrase.\n\n"
            "The phrase will be checked locally and will not be "
            "saved until you explicitly choose to save the wallet "
            "to encrypted storage."
        )
        instructions.setWordWrap(True)

        phrase_input = QLineEdit()
        phrase_input.setPlaceholderText(
            "Enter recovery phrase"
        )
        phrase_input.setEchoMode(QLineEdit.Normal)
        phrase_input.setMinimumHeight(40)

        import_button = QPushButton(
            "Import Recovery Phrase"
        )
        import_button.setMinimumHeight(42)
        import_button.clicked.connect(
            lambda: self.import_recovery_phrase(
                phrase_input.text()
            )
        )

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(
            self.show_create_wallet
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(20)
        self.layout.addWidget(phrase_input)
        self.layout.addSpacing(15)
        self.layout.addWidget(import_button)
        self.layout.addWidget(back)
        self.layout.addStretch()

        phrase_input.setFocus()


    def generate_wallet_phrase(self, num_words):
        try:
            mnemonic = generate_recovery_phrase(num_words)
        except Exception as e:
            self.show_error(
                f"Unable to generate a recovery phrase:\n\n{e}"
            )
            return

        self.show_generated_phrase(mnemonic)


    def start_wallet_creation(self, num_words):
        self.generate_wallet_phrase(num_words)


    def show_generated_phrase(self, mnemonic):
        self.clear_layout()
        self.resize(600, 650)

        title = QLabel("Recovery Phrase")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        warning = QLabel(
            "WRITE THESE WORDS DOWN AND KEEP THEM OFFLINE.\n\n"
            "This recovery phrase has not been saved to the signer.\n\n"
            "Anyone with this recovery phrase can control the wallet. "
            "Never photograph it, copy it to an online device, or give it to another person."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        phrase_label = QLabel(mnemonic)
        phrase_label.setWordWrap(True)
        phrase_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse
        )
        phrase_label.setStyleSheet(
            "font-size: 16px; padding: 15px; border: 2px solid gray;"
        )

        copy_button = QPushButton("Copy Seed Phrase")
        copy_button.setMinimumHeight(42)
        copy_button.clicked.connect(
            lambda: self.copy_text(mnemonic)
        )

        copy_warning = QLabel(
            "If you copy the seed phrase, clear the clipboard immediately after use."
        )
        copy_warning.setWordWrap(True)
        copy_warning.setStyleSheet(
            "font-size: 11px; font-weight: bold;"
        )

        verify = QPushButton(
            "I Have Written Down the Phrase"
        )
        verify.setMinimumHeight(42)
        verify.clicked.connect(
            lambda: self.show_phrase_verification(
                mnemonic
            )
        )

        discard = QPushButton("Discard")
        discard.setMinimumHeight(42)
        discard.clicked.connect(self.show_home)

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(20)
        self.layout.addWidget(phrase_label)
        self.layout.addSpacing(10)
        self.layout.addWidget(copy_button)
        self.layout.addWidget(copy_warning)
        self.layout.addSpacing(15)
        self.layout.addWidget(verify)
        self.layout.addWidget(discard)
        self.layout.addStretch()


    def show_phrase_verification(self, mnemonic):
        self.clear_layout()

        title = QLabel("Verify Recovery Phrase")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Enter the recovery phrase again to verify that it was "
            "recorded correctly.\n\n"
            "The phrase is checked locally."
        )
        instructions.setWordWrap(True)

        phrase_input = QLineEdit()
        phrase_input.setPlaceholderText(
            "Enter recovery phrase"
        )
        phrase_input.setEchoMode(QLineEdit.Normal)
        phrase_input.setMinimumHeight(40)

        verify = QPushButton("Verify")
        verify.setMinimumHeight(42)
        verify.clicked.connect(
            lambda: self.verify_generated_phrase(
                mnemonic,
                phrase_input.text(),
            )
        )

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(
            lambda: self.show_generated_phrase(
                mnemonic
            )
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(18)
        self.layout.addWidget(phrase_input)
        self.layout.addSpacing(18)
        self.layout.addWidget(verify)
        self.layout.addWidget(back)
        self.layout.addStretch()

        phrase_input.setFocus()


    def verify_generated_phrase(
        self,
        original_phrase,
        entered_phrase,
    ):
        entered_phrase = entered_phrase.strip()

        if not entered_phrase:
            self.show_error(
                "No recovery phrase was entered."
            )
            return

        if entered_phrase != original_phrase:
            self.show_phrase_verification_error(
                original_phrase
            )
            return

        self.session_mnemonic = original_phrase
        self.session_is_persistent = False
        self.show_signer_ready(original_phrase)


    def show_phrase_verification_error(
        self,
        mnemonic,
    ):
        self.clear_layout()

        title = QLabel("Verification Failed")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        message = QLabel(
            "The recovery phrase you entered does not match "
            "the generated phrase.\n\n"
            "Do not continue until the phrase has been recorded correctly."
        )
        message.setWordWrap(True)

        retry = QPushButton("Try Again")
        retry.setMinimumHeight(42)
        retry.clicked.connect(
            lambda: self.show_phrase_verification(
                mnemonic
            )
        )

        discard = QPushButton("Discard")
        discard.setMinimumHeight(42)
        discard.clicked.connect(self.show_home)

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(message)
        self.layout.addSpacing(25)
        self.layout.addWidget(retry)
        self.layout.addWidget(discard)
        self.layout.addStretch()



    def show_signer_ready(self, mnemonic):
        self.clear_layout()
        self.resize(600, 620)

        title = QLabel(
            "Wallet Ready"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        if self.session_is_persistent:
            wallet_name = self.active_wallet_name
            storage_status = "Encrypted wallet storage"
            session_status = "Persistent wallet"
        else:
            wallet_name = "New wallet"
            storage_status = "Not saved"
            session_status = "New wallet"

        wallet_info_text = (
            f"<b>Wallet:</b> {wallet_name}<br>"
            f"<b>Storage:</b> {storage_status}<br>"
            f"<b>Status:</b> {session_status}"
        )

        if (
            not self.session_is_persistent
            and self.active_wallet_name is not None
        ):
            wallet_info_text += (
                f"<br><b>Stored wallet:</b> "
                f"{self.active_wallet_name}"
            )

        wallet_info = QLabel(
            wallet_info_text
        )
        wallet_info.setWordWrap(True)
        wallet_info.setMinimumHeight(65)

        message = QLabel(
            "The recovery phrase is currently available for signing."
        )
        message.setWordWrap(True)

        # Wallet Storage

        if IS_LINUX:
            storage_title = QLabel(
                "Wallet Storage"
            )
            storage_title.setStyleSheet(
                "font-size: 17px; font-weight: bold;"
            )

            if self.session_is_persistent:
                storage_message = QLabel(
                    "This wallet is saved on the encrypted storage device. "
                    "The recovery phrase will be available again when the "
                    "encrypted storage is unlocked."
                )
                storage_message.setWordWrap(True)

                save_button = QPushButton(
                    "Wallet Saved to Encrypted Storage"
                )
                save_button.setEnabled(False)

            else:
                storage_message = QLabel(
                    "This wallet is currently session-only and has not been "
                    "saved to encrypted storage."
                )
                storage_message.setWordWrap(True)

                save_button = QPushButton(
                    "Save Wallet to Encrypted Storage"
                )
                save_button.setMinimumHeight(42)
                save_button.clicked.connect(
                    lambda: self.save_wallet_to_storage(
                        mnemonic
                    )
                )

            session_button = QPushButton(
                "Use as Session-Only Wallet"
            )
            session_button.setMinimumHeight(42)

            if self.session_is_persistent:
                session_button.setEnabled(False)
            else:
                session_button.clicked.connect(
                    lambda: self.confirm_session_only_wallet(
                        mnemonic
                    )
                )

        # Switch Wallet

        if IS_LINUX:
            archive_title = QLabel(
                "Switch Wallet"
            )
            archive_title.setStyleSheet(
                "font-size: 17px; font-weight: bold;"
            )

            archive_message = QLabel(
                "Select a previously saved wallet from encrypted storage."
            )
            archive_message.setWordWrap(True)

            self.archive_combo = QComboBox()
            self.archive_combo.setMinimumHeight(42)

            self.archive_combo.addItem(
                "Select archived wallet..."
            )

            if self.storage_mount_path is not None:
                archive_directory = get_archive_directory()

                if os.path.isdir(
                    archive_directory
                ):
                    for wallet_id in os.listdir(
                        archive_directory
                    ):
                        wallet_directory = os.path.join(
                            archive_directory,
                            wallet_id,
                        )

                        metadata_path = os.path.join(
                            wallet_directory,
                            "wallet.json",
                        )

                        if not os.path.isfile(
                            metadata_path
                        ):
                            continue

                        with open(
                            metadata_path,
                            "r",
                            encoding="utf-8",
                        ) as file:
                            metadata = json.load(
                                file
                            )

                        wallet_name = metadata.get(
                            "wallet_name",
                            "",
                        ).strip()

                        if wallet_name:
                            self.archive_combo.addItem(
                                wallet_name,
                                wallet_id,
                            )

            load_wallet_button = QPushButton(
                "Load Selected Wallet"
            )
            load_wallet_button.setMinimumHeight(42)
            load_wallet_button.clicked.connect(
                lambda: self.load_selected_wallet(
                    self.archive_combo.currentData()
                )
            )

            delete_wallet_button = QPushButton(
                "Delete Selected Wallet"
            )
            delete_wallet_button.setMinimumHeight(42)
            delete_wallet_button.clicked.connect(
                lambda: self.delete_selected_wallet(
                    self.archive_combo.currentData()
                )
            )



        # Key Export

        export_title = QLabel(
            "Key Export"
        )
        export_title.setStyleSheet(
            "font-size: 17px; font-weight: bold;"
        )

        export_combo = QComboBox()
        export_combo.addItem(
            "Select key export action..."
        )

        export_combo.addItem(
            "View Master Public Key",
            "public",
        )

        export_combo.addItem(
            "Reveal Master Private Key",
            "private",
        )

        export_combo.addItem(
            "View Recovery Seed",
            "seed",
        )

        def handle_key_export(index):
            action = export_combo.itemData(
                index
            )

            if action == "public":
                export_combo.setCurrentIndex(0)

                self.show_master_public_key_warning(
                    mnemonic,
                    lambda: self.show_signer_ready(
                        mnemonic
                    ),
                )

            elif action == "private":
                export_combo.setCurrentIndex(0)

                self.show_private_key_warning(
                    mnemonic
                )

            elif action == "seed":
                export_combo.setCurrentIndex(0)

                self.show_recovery_seed_warning(
                    mnemonic
                )

        export_combo.currentIndexChanged.connect(
            handle_key_export
        )


        # Bottom Navigation

        clear_session = QPushButton(
            "Clear Session"
        )
        clear_session.setMinimumHeight(32)
        clear_session.clicked.connect(
            self.clear_session
        )

        home = QPushButton(
            "Return Home"
        )
        home.setMinimumHeight(32)
        home.clicked.connect(
            self.show_home
        )

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(
            clear_session
        )
        bottom_layout.addWidget(
            home
        )

        # Main Layout

        self.layout.addWidget(
            title
        )
        self.layout.addSpacing(4)

        self.layout.addWidget(
            wallet_info
        )
        self.layout.addSpacing(15)

        self.layout.addWidget(
            message
        )
        self.layout.addSpacing(20)

        # Wallet Storage

        if IS_LINUX:
            self.layout.addWidget(
                storage_title
            )
            self.layout.addWidget(
                storage_message
            )
            self.layout.addSpacing(10)

            self.layout.addWidget(
                save_button
            )
            self.layout.addWidget(
                session_button
            )
            self.layout.addSpacing(12)

            # Switch Wallet

            self.layout.addWidget(
                archive_title
            )
            self.layout.addWidget(
                archive_message
            )
            self.layout.addWidget(
                self.archive_combo
            )
            self.layout.addWidget(
                load_wallet_button
            )
            self.layout.addWidget(
                delete_wallet_button
            )
            self.layout.addSpacing(12)

        # Key Export

        self.layout.addWidget(
            export_title
        )
        self.layout.addWidget(
            export_combo
        )
        self.layout.addSpacing(15)


        # Bottom Navigation

        self.layout.addLayout(
            bottom_layout
        )

        self.layout.addStretch()


    # ------------------------------------------------------------------
    # Multisig destination derivation tool
    # ------------------------------------------------------------------


    def show_multisig_derivation_tool(
        self,
        return_callback=None,
    ):
        if return_callback is None:
            return_callback = self.show_home

        self.clear_layout()
        self.resize(700, 750)

        title = QLabel("Multisig Destination Derivation")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        instructions = QLabel(
            "Derive ElectrumSVP bare multisig destinations from cosigner extended public keys.\n\n"
            "Public keys are derived locally, sorted according to ElectrumSVP's multisig rules, "
            "and encoded as bitcoin-script BIP276 destinations. No private keys are required."
        )
        instructions.setWordWrap(True)

        threshold_spin = QSpinBox()
        threshold_spin.setRange(1, 15)
        threshold_spin.setValue(2)
        threshold_spin.setMinimumHeight(40)

        cosigner_count_spin = QSpinBox()
        cosigner_count_spin.setRange(2, 15)
        cosigner_count_spin.setValue(2)
        cosigner_count_spin.setMinimumHeight(32)

        branch_combo = QComboBox()
        branch_combo.addItem("Receiving (m/0/index)", 0)
        branch_combo.addItem("Change (m/1/index)", 1)
        branch_combo.setMinimumHeight(40)

        start_spin = QSpinBox()
        start_spin.setRange(0, 1000000)
        start_spin.setValue(0)
        start_spin.setMinimumHeight(32)

        count_spin = QSpinBox()
        count_spin.setRange(1, 100)
        count_spin.setValue(10)
        count_spin.setMinimumHeight(32)

        form = QGridLayout()

        form.addWidget(
            QLabel("Required signatures:"),
            0,
            0,
        )
        form.addWidget(
            threshold_spin,
            0,
            1,
        )

        form.addWidget(
            QLabel("Number of cosigners:"),
            1,
            0,
        )
        form.addWidget(
            cosigner_count_spin,
            1,
            1,
        )

        form.addWidget(
            QLabel("Branch:"),
            2,
            0,
        )
        form.addWidget(
            branch_combo,
            2,
            1,
        )

        form.addWidget(
            QLabel("Starting index:"),
            3,
            0,
        )
        form.addWidget(
            start_spin,
            3,
            1,
        )

        form.addWidget(
            QLabel("Number of destinations:"),
            4,
            0,
        )
        form.addWidget(
            count_spin,
            4,
            1,
        )

        self.layout.addWidget(title)
        self.layout.addSpacing(8)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(15)
        self.layout.addLayout(form)
        self.layout.addSpacing(15)

        xpub_title = QLabel("Cosigner extended public keys")
        xpub_title.setStyleSheet(
            "font-size: 14px; font-weight: bold;"
        )
        self.layout.addWidget(xpub_title)
        self.layout.addSpacing(6)

        xpub_inputs = []
        xpub_rows = []

        xpub_container = QWidget()
        xpub_layout = QVBoxLayout(xpub_container)
        xpub_layout.setContentsMargins(0, 0, 0, 0)
        xpub_layout.setSpacing(6)
        xpub_layout.setAlignment(
            Qt.AlignTop
        )

        for index in range(15):
            row_widget = QWidget()

            row = QHBoxLayout(row_widget)
            row.setContentsMargins(0, 0, 0, 0)

            label = QLabel(
                f"Cosigner {index + 1}:"
            )
            label.setMinimumWidth(90)

            xpub_input = QLineEdit()
            xpub_input.setPlaceholderText(
                "xpub..."
            )
            xpub_input.setMinimumHeight(38)

            row.addWidget(label)
            row.addWidget(xpub_input)

            xpub_layout.addWidget(
                row_widget
            )

            xpub_inputs.append(
                xpub_input
            )
            xpub_rows.append(
                row_widget
            )

        xpub_scroll = QScrollArea()
        xpub_scroll.setWidgetResizable(True)
        xpub_scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarAsNeeded
        )
        xpub_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )
        xpub_scroll.setWidget(
            xpub_container
        )
        xpub_scroll.setMinimumHeight(250)
        xpub_scroll.setMaximumHeight(400)

        self.layout.addWidget(
            xpub_scroll
        )

        def update_cosigner_visibility():
            count = cosigner_count_spin.value()

            for index, row_widget in enumerate(xpub_rows):
                row_widget.setVisible(
                    index < count
                )

            if threshold_spin.value() > count:
                threshold_spin.setValue(
                    count
                )

            threshold_spin.setMaximum(
                count
            )

        cosigner_count_spin.valueChanged.connect(
            update_cosigner_visibility
        )

        update_cosigner_visibility()

        self.layout.addSpacing(15)

        derive_button = QPushButton(
            "Derive Multisig Destinations"
        )
        derive_button.setMinimumHeight(42)

        def derive():
            cosigner_count = cosigner_count_spin.value()
            threshold = threshold_spin.value()
            branch = branch_combo.currentData()
            start_index = start_spin.value()
            count = count_spin.value()

            xpubs = []

            for index in range(cosigner_count):
                xpub = xpub_inputs[index].text().strip()

                if not xpub:
                    self.show_error(
                        f"Cosigner {index + 1} xpub is required."
                    )
                    return

                xpubs.append(xpub)

            if threshold < 1 or threshold > cosigner_count:
                self.show_error(
                    "The required signature count must be between "
                    "1 and the number of cosigners."
                )
                return

            rows = []

            try:
                for address_index in range(
                    start_index,
                    start_index + count,
                ):
                    path = (
                        branch,
                        address_index,
                    )

                    pubkeys = []

                    for xpub in xpubs:
                        key = bip32_key_from_string(xpub)

                        for path_index in path:
                            key = key.child(path_index)

                        pubkeys.append(
                            key.public_key
                        )

                    sorted_pubkeys = sorted(
                        pubkeys,
                        key=lambda key: key.to_hex(),
                    )

                    output = P2MultiSig_Output(
                        [
                            key.to_bytes()
                            for key in sorted_pubkeys
                        ],
                        threshold,
                    )

                    script = output.to_script_bytes()

                    destination = bip276_encode(
                        PREFIX_BIP276_SCRIPT,
                        script,
                        Net.BIP276_VERSION,
                    )

                    rows.append(
                        {
                            "index": address_index,
                            "branch": branch,
                            "path": (
                                f"m/{branch}/{address_index}"
                            ),
                            "public_keys": [
                                key.to_hex()
                                for key in sorted_pubkeys
                            ],
                            "destination": destination,
                        }
                    )

            except Exception as e:
                self.show_error(
                    f"Unable to derive multisig destinations:\n\n{e}"
                )
                return

            self.show_multisig_derivation_results(
                rows,
                threshold,
                cosigner_count,
                return_callback,
            )

        derive_button.clicked.connect(derive)

        self.layout.addWidget(
            derive_button
        )

        back_button = QPushButton("Back")
        back_button.setMinimumHeight(40)
        back_button.clicked.connect(
            self.show_home
        )

        self.layout.addSpacing(10)
        self.layout.addWidget(
            back_button
        )

        self.layout.addStretch()



    # ------------------------------------------------------------------
    # Multisig derivation results
    # ------------------------------------------------------------------

    def show_multisig_derivation_results(
        self,
        rows,
        threshold,
        cosigner_count,
        return_callback,
    ):
        self.clear_layout()
        self.resize(700, 750)

        title = QLabel(
            "Multisig Derivation Results"
        )
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        summary = QLabel(
            f"{threshold}-of-{cosigner_count} multisig"
        )
        summary.setStyleSheet(
            "font-size: 14px; font-weight: bold;"
        )

        self.layout.addWidget(title)
        self.layout.addWidget(summary)
        self.layout.addSpacing(12)

        results = QTextBrowser()
        results.setOpenLinks(False)
        results.setOpenExternalLinks(False)
        results.setReadOnly(True)
        results.setMinimumHeight(500)

        html = []

        for row in rows:
            html.append(
                f"<b>{row['path']}</b><br>"
            )

            html.append(
                "<b>Public keys:</b><br>"
            )

            for key_index, public_key in enumerate(
                row["public_keys"]
            ):
                html.append(
                    f"&nbsp;&nbsp;{public_key} "
                    f"<a href='pubqr:{row['index']}:{key_index}'>"
                    f"[ QR ]</a><br>"
                )

            html.append(
                "<br><b>Destination:</b><br>"
            )

            html.append(
                f"{row['destination']} "
                f"<a href='qr:{row['index']}'>[ QR ]</a><br>"
            )

            html.append(
                "<hr>"
            )

        results.setHtml(
            "".join(html)
        )

        def handle_link(url):
            url = url.toString()

            if url.startswith("pubqr:"):
                parts = url.split(":")

                index = int(parts[1])
                key_index = int(parts[2])

                row = next(
                    row
                    for row in rows
                    if row["index"] == index
                )

                public_key = row["public_keys"][key_index]

                self.show_text_qr(
                    f"Public Key QR - {row['path']}",
                    public_key,
                    "Compressed public key encoded as a standard QR code.",
                    False,
                    lambda: self.show_multisig_derivation_results(
                        rows,
                        threshold,
                        cosigner_count,
                        return_callback,
                    ),
                )

                return

            if not url.startswith("qr:"):
                return

            index = int(
                url.split(":", 1)[1]
            )

            row = next(
                row
                for row in rows
                if row["index"] == index
            )

            self.show_text_qr(
                f"Multisig QR - {row['path']}",
                row["destination"],
                "ElectrumSVP bare multisig destination encoded as a standard QR code.",
                False,
                lambda: self.show_multisig_derivation_results(
                    rows,
                    threshold,
                    cosigner_count,
                    return_callback,
                ),
            )

        results.anchorClicked.connect(
            handle_link
        )

        self.layout.addWidget(
            results
        )

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(40)
        back_button.clicked.connect(
            lambda: self.show_multisig_derivation_tool(
                return_callback
            )
        )

        self.layout.addSpacing(10)
        self.layout.addWidget(
            back_button
        )

        self.layout.addStretch()




    # ------------------------------------------------------------------
    # Address and private-key derivation tool
    # ------------------------------------------------------------------


    def show_derivation_tool(
        self,
        mnemonic=None,
        return_callback=None,
    ):
        if not mnemonic:
            mnemonic = self.session_mnemonic

        if return_callback is None:
            return_callback = self.show_home

        self.clear_layout()
        self.resize(650, 650)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        content_layout = QVBoxLayout(content)

        scroll.setWidget(content)
        self.layout.addWidget(scroll)

        title = QLabel("Address & Key Derivation")

        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        instructions = QLabel(
            "Derive Bitcoin SV P2PKH addresses and their corresponding private keys from a BIP39 seed.\n\n"
            "Everything is derived locally. The seed is not saved. Private keys should be treated as highly sensitive."
        )
        instructions.setWordWrap(True)

        seed_input = QLineEdit()
        seed_input.setPlaceholderText("BIP39 seed phrase")
        seed_input.setEchoMode(QLineEdit.Normal)
        seed_input.setMinimumHeight(32)
        seed_input.setMinimumWidth(200)

        if mnemonic:
            seed_input.setText(mnemonic)

        path_input = QLineEdit(DEFAULT_ACCOUNT_DERIVATION)
        path_input.setMinimumHeight(32)
        path_input.setMinimumWidth(200)

        branch_input = QLineEdit("0")
        branch_input.setMinimumHeight(32)
        branch_input.setMinimumWidth(200)
        branch_input.setPlaceholderText("0 = receiving, 1 = change")

        start_spin = QSpinBox()
        start_spin.setRange(0, 1000000)
        start_spin.setValue(0)
        start_spin.setMinimumHeight(32)

        count_spin = QSpinBox()
        count_spin.setRange(1, 100)
        count_spin.setValue(10)
        count_spin.setMinimumHeight(32)

        form = QGridLayout()
        form.setColumnStretch(0, 0)
        form.setColumnStretch(1, 1)

        form.addWidget(QLabel("BIP39 seed:"), 0, 0)
        form.addWidget(seed_input, 0, 1)
        form.addWidget(QLabel("Account path:"), 1, 0)
        form.addWidget(path_input, 1, 1)
        form.addWidget(QLabel("Branch:"), 2, 0)
        form.addWidget(branch_input, 2, 1)
        form.addWidget(QLabel("Starting index:"), 3, 0)
        form.addWidget(start_spin, 3, 1)
        form.addWidget(QLabel("Number of addresses:"), 4, 0)
        form.addWidget(count_spin, 4, 1)

        example = QLabel(
            "Receiving: account path + /0/index\n"
            "Change:    account path + /1/index\n\n"
            "Example: m/44'/0'/0' + /0/5 = m/44'/0'/0'/0/5"
        )
        example.setStyleSheet("font-size: 11px;")
        example.setWordWrap(True)

        export_title = QLabel("Master Key Export")
        export_title.setStyleSheet(
            "font-size: 15px; font-weight: bold;"
        )

        export_message = QLabel(
            "The master public key can be exported to create a watch-only wallet. "
            "The master private key is highly sensitive."
        )
        export_message.setWordWrap(True)
        export_message.setStyleSheet("font-size: 11px;")

        public_button = QPushButton(
            "View Master Public Key"
        )
        public_button.setMinimumHeight(40)

        def show_public_key_warning():
            seed = seed_input.text()

            self.show_master_public_key_warning(
                seed,
                lambda: self.show_derivation_tool(
                    seed,
                    return_callback,
                ),
            )

        public_button.clicked.connect(
            show_public_key_warning
        )

        private_button = QPushButton(
            "Reveal Master Private Key"
        )
        private_button.setMinimumHeight(40)
        private_button.clicked.connect(
            lambda: self.export_master_private_from_seed(
                seed_input.text()
            )
        )

        qr_title = QLabel("Text to QR:")

        qr_input = QLineEdit()
        qr_input.setPlaceholderText(
            "Enter or paste text"
        )
        qr_input.setMinimumHeight(32)

        qr_button = QPushButton(
            "Display QR"
        )
        qr_button.setMinimumHeight(32)

        def translate_text():
            text = qr_input.text().strip()

            if not text:
                self.show_error("No text was entered.")
                return

            self.show_text_qr(
                "Text QR Code",
                text,
                "The text below has been encoded into a standard QR code.",
                False,
                lambda: self.show_derivation_tool(
                    mnemonic,
                    return_callback,
                ),
            )

        qr_button.clicked.connect(translate_text)

        qr_row = QHBoxLayout()
        qr_row.addWidget(qr_title)
        qr_row.addWidget(qr_input, 1)
        qr_row.addWidget(qr_button)


        derive = QPushButton(
            "Derive Addresses"
        )
        derive.setMinimumHeight(36)
        derive.clicked.connect(
            lambda: self.derive_addresses(
                seed_input.text(),
                path_input.text(),
                branch_input.text(),
                start_spin.value(),
                count_spin.value(),
            )
        )

        back_button = QPushButton(
            "Back"
        )
        back_button.setMinimumHeight(32)
        back_button.clicked.connect(
            return_callback
        )

        content_layout.addWidget(title)
        content_layout.addSpacing(10)
        content_layout.addWidget(instructions)
        content_layout.addSpacing(15)
        content_layout.addLayout(form)
        content_layout.addSpacing(10)
        content_layout.addWidget(example)

        content_layout.addSpacing(12)
        content_layout.addWidget(export_title)
        content_layout.addWidget(export_message)
        content_layout.addWidget(public_button)
        content_layout.addSpacing(1)
        content_layout.addWidget(private_button)
        content_layout.addSpacing(1)
        content_layout.addWidget(derive)

        content_layout.addSpacing(12)
        content_layout.addLayout(qr_row)

        content_layout.addSpacing(15)
        content_layout.addWidget(back_button)

        content_layout.addStretch()

        seed_input.setFocus()


    def export_master_private_from_seed(self, mnemonic):
        mnemonic = mnemonic.strip()

        if not mnemonic:
            self.show_error("No BIP39 seed was entered.")
            return

        self.show_private_key_warning(mnemonic)


    def derive_addresses(self, mnemonic, account_path, branch_text, start_index, count):
        mnemonic = mnemonic.strip()
        account_path = account_path.strip()
        branch_text = branch_text.strip()

        if not mnemonic:
            self.show_error("No BIP39 seed was entered.")
            return
        if branch_text not in ("0", "1"):
            self.show_error("Branch must be 0 for receiving or 1 for change.")
            return

        try:
            account_indexes = self.parse_derivation_path(account_path)
            master_key = self.derive_master_key(mnemonic)
            account_key = master_key
            for index in account_indexes:
                account_key = account_key.child_safe(index)

            rows = []
            branch = int(branch_text)
            for index in range(start_index, start_index + count):
                child_path = account_path + f"/{branch}/{index}"
                child_key = account_key.child_safe(branch).child_safe(index)
                public_key = child_key.public_key
                address = self.public_key_to_address(public_key)
                wif = self.private_key_wif(child_key)
                rows.append((child_path, address, wif, public_key.to_hex()))

        except Exception as e:
            self.show_error(f"Unable to derive addresses:\n\n{e}")
            return

        self.show_derivation_results(rows, account_path, branch)


    def show_derivation_results(self, rows, account_path, branch):
        self.clear_layout()
        self.resize(850, 800)

        title = QLabel("Derived Addresses & Keys")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: Private keys control the corresponding addresses. "
            "Only select Private WIF when you specifically need it."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        options_label = QLabel("Include in results:")
        options_label.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        path_check = QCheckBox("Derivation Path")
        path_check.setChecked(True)

        address_check = QCheckBox("Address")
        address_check.setChecked(True)

        wif_check = QCheckBox("Private WIF")
        wif_check.setChecked(False)

        pubkey_check = QCheckBox("Public Key")
        pubkey_check.setChecked(False)

        output = QTextBrowser()
        output.setReadOnly(True)
        output.setMinimumHeight(400)
        output.setStyleSheet("font-size: 10px;")

        def qr_link(index, key_type):
            return (
                f'<a href="qr:{key_type}:{index}" '
                f'style="text-decoration: none;">'
                f'[ QR ]'
                f'</a>'
            )

        def build_output():
            lines = [
                f"Account path: {account_path}",
                f"Branch: /{branch}",
                "",
            ]

            for index, (path, address, wif, pubkey) in enumerate(rows):
                entry = []

                if path_check.isChecked():
                    entry.append(
                        f"Path:       {path}"
                    )

                if address_check.isChecked():
                    entry.append(
                        f"Address:    {address} "
                        f"{qr_link(index, 'address')}"
                    )

                if wif_check.isChecked():
                    entry.append(
                        f"Private WIF: {wif} "
                        f"{qr_link(index, 'wif')}"
                    )

                if pubkey_check.isChecked():
                    entry.append(
                        f"Public key: {pubkey} "
                        f"{qr_link(index, 'pubkey')}"
                    )

                if entry:
                    lines.extend(entry)
                    lines.append("")

            return "\n".join(lines)

        def update_output():
            output.setHtml(
                build_output().replace(
                    "\n",
                    "<br>"
                )
            )

        def handle_qr_link(url):
            link = url.toString()

            if not link.startswith("qr:"):
                return

            parts = link.split(":")

            if len(parts) != 3:
                return

            try:
                index = int(parts[2])
            except ValueError:
                return

            if index < 0 or index >= len(rows):
                return

            path, address, wif, pubkey = rows[index]

            if parts[1] == "address":
                self.show_text_qr(
                    "Address QR Code",
                    address,
                    "The derived Bitcoin SV address has been encoded into a standard QR code.",
                    False,
                    lambda: self.show_derivation_results(
                        rows,
                        account_path,
                        branch,
                    ),
                )

            elif parts[1] == "wif":
                self.show_text_qr(
                    "Private WIF QR Code",
                    wif,
                    "WARNING: This QR code contains a private key. "
                    "Anyone who obtains it may be able to spend funds.",
                    True,
                    lambda: self.show_derivation_results(
                        rows,
                        account_path,
                        branch,
                    ),
                )


            elif parts[1] == "pubkey":
                self.show_text_qr(
                    "Public Key QR Code",
                    pubkey,
                    "The derived public key has been encoded into a standard QR code.",
                    False,
                    lambda: self.show_derivation_results(
                        rows,
                        account_path,
                        branch,
                    ),
                )


        output.anchorClicked.connect(handle_qr_link)

        path_check.stateChanged.connect(update_output)
        address_check.stateChanged.connect(update_output)
        wif_check.stateChanged.connect(update_output)
        pubkey_check.stateChanged.connect(update_output)

        update_output()

        copy = QPushButton("Copy Selected Results")
        copy.setMinimumHeight(40)
        copy.clicked.connect(
            lambda: self.copy_text(
                build_output()
                .replace(
                    "\n",
                    "\n"
                )
            )
        )

        save = QPushButton("Save Selected Results")
        save.setMinimumHeight(40)

        def save_results():
            sensitive = wif_check.isChecked()

            if sensitive:
                self.show_derivation_save_warning(
                    build_output()
                    .replace(
                        "\n",
                        "\n"
                    ),
                    account_path,
                    branch,
                )
                return

            self.save_text_to_file(
                build_output()
                .replace(
                    "\n",
                    "\n"
                ),
                "Save Derived Addresses",
                "electrumsvp-addresses.txt",
            )

        save.clicked.connect(save_results)

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(self.show_home)

        self.layout.addWidget(title)
        self.layout.addSpacing(10)
        self.layout.addWidget(warning)
        self.layout.addSpacing(10)
        self.layout.addWidget(options_label)
        self.layout.addWidget(path_check)
        self.layout.addWidget(address_check)
        self.layout.addWidget(wif_check)
        self.layout.addWidget(pubkey_check)
        self.layout.addSpacing(10)
        self.layout.addWidget(output)
        self.layout.addWidget(copy)
        self.layout.addWidget(save)
        self.layout.addWidget(back)


    def show_derivation_save_warning(
        self,
        text,
        account_path,
        branch,
    ):
        self.clear_layout()
        self.resize(600, 600)

        title = QLabel("Save Private Key Data")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: YOUR SELECTED RESULTS INCLUDE PRIVATE KEYS.\n\n"
            "Anyone who obtains this file may be able to spend funds "
            "from the corresponding addresses.\n\n"
            "Only save this file to secure offline storage. "
            "Do not save it to an online computer or cloud storage."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        save = QPushButton("Save Private Key Data")
        save.setMinimumHeight(42)

        def save_private_results():
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Derived Private Key Data",
                "electrumsvp-addresses-private.txt",
                "Text Files (*.txt);;All Files (*)",
            )

            if not path:
                return

            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            except Exception as e:
                self.show_error(
                    f"Unable to save the derived private key data:\n\n{e}"
                )
                return

            self.show_derivation_results_after_save(
                text,
                account_path,
                branch,
            )

            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            except Exception as e:
                self.show_error(
                    f"Unable to save the derived private key data:\n\n{e}"
                )
                return

            self.show_derivation_tool()

        save.clicked.connect(save_private_results)

        cancel = QPushButton("Cancel")
        cancel.setMinimumHeight(42)
        cancel.clicked.connect(
            lambda: self.show_derivation_tool()
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(25)
        self.layout.addWidget(save)
        self.layout.addWidget(cancel)
        self.layout.addStretch()



    # ------------------------------------------------------------------
    # Master key export
    # ------------------------------------------------------------------

    def show_master_public_key_warning(self, mnemonic, return_callback):
        self.clear_layout()
        self.resize(600, 600)

        title = QLabel("Master Public Key")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        warning = QLabel(
            "The master public key cannot be used by itself to spend funds.\n\n"
            "However, anyone who obtains it can derive the wallet's public keys "
            "and addresses and monitor the wallet's activity.\n\n"
            "The master public key also covers the wallet's entire public "
            "derivation tree. Only export it when you understand this exposure.\n\n"
            "For a watch-only wallet, consider whether an account-level public "
            "key is sufficient for your intended use."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        continue_button = QPushButton("Show Master Public Key")
        continue_button.setMinimumHeight(42)
        continue_button.clicked.connect(
            lambda: self.show_master_public_key(
                mnemonic,
                return_callback,
            )
        )

        cancel = QPushButton("Cancel")
        cancel.setMinimumHeight(42)
        cancel.clicked.connect(return_callback)

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(25)
        self.layout.addWidget(continue_button)
        self.layout.addWidget(cancel)
        self.layout.addStretch()


    def show_master_public_key(self, mnemonic, return_callback):
        try:
            xpub = self.key_to_xpub(self.derive_master_key(mnemonic))
        except Exception as e:
            self.show_error(
                f"Unable to derive the master public key:\n\n{e}"
            )
            return

        self.show_key_qr(
            "Master Public Key",
            xpub,
            "This is the master extended public key.\n\n"
            "It can be exported to an online wallet to create a watch-only wallet.",
            False,
            return_callback,
        )

    def show_private_key_warning(self, mnemonic):
        self.clear_layout()
        title = QLabel("Master Private Key")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        warning = QLabel(
            "WARNING: THIS KEY IS HIGHLY SENSITIVE.\n\n"
            "Anyone who obtains the master private key can derive the wallet's private keys and spend funds.\n\n"
            "Only reveal or copy this key when you understand exactly why it is needed."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("font-size: 13px; font-weight: bold;")
        reveal = QPushButton("Reveal Master Private Key")
        reveal.setMinimumHeight(42)
        reveal.clicked.connect(lambda: self.show_master_private_key(mnemonic))
        cancel = QPushButton("Cancel")
        cancel.setMinimumHeight(42)
        cancel.clicked.connect(lambda: self.show_signer_ready(mnemonic))
        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(25)
        self.layout.addWidget(reveal)
        self.layout.addWidget(cancel)
        self.layout.addStretch()

    def show_master_private_key(self, mnemonic):
        try:
            xprv = self.key_to_xprv(self.derive_master_key(mnemonic))
        except Exception as e:
            self.show_error(f"Unable to derive the master private key:\n\n{e}")
            return
        self.show_key_qr(
            "Master Private Key",
            xprv,
            "WARNING: Anyone with this key can derive the wallet's private keys and spend funds.\n\n"
            "Do not enter this key into an online device unless you fully understand the consequences.",
            True,
            lambda: self.show_signer_ready(mnemonic),
        )

    def show_key_qr(self, title, key_text, description, sensitive, return_callback):
        self.clear_layout()
        self.resize(650, 800)

        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 20px; font-weight: bold;")

        description_label = QLabel(description)
        description_label.setWordWrap(True)

        key_label = QLabel(key_text)
        key_label.setWordWrap(True)
        key_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        key_label.setStyleSheet(
            "font-size: 11px; padding: 10px; border: 1px solid gray;"
        )

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=4,
        )
        qr.add_data(key_text)
        qr.make(fit=True)

        qr_path = "signer/key_export.png"
        qr.make_image().convert("RGB").save(qr_path)

        qr_label = QLabel()
        qr_label.setPixmap(
            QPixmap(qr_path).scaled(
                420,
                420,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )
        qr_label.setAlignment(Qt.AlignCenter)

        copy = QPushButton("Copy Key")
        copy.setMinimumHeight(40)
        copy.clicked.connect(lambda: self.copy_text(key_text))

        save = QPushButton("Save Key to File")
        save.setMinimumHeight(40)

        def save_key():
            if sensitive:
                self.show_private_key_save_warning(
                    key_text,
                    title,
                    return_callback,
                )
                return

            self.save_text_to_file(
                key_text,
                "Save Master Public Key",
                "electrumsvp-master-xpub.txt",
            )

        save.clicked.connect(save_key)

        back = QPushButton("Back")
        back.setMinimumHeight(40)
        back.clicked.connect(return_callback)

        self.layout.addWidget(title_label)
        self.layout.addWidget(description_label)
        self.layout.addWidget(key_label)
        self.layout.addWidget(qr_label)
        self.layout.addWidget(copy)
        self.layout.addWidget(save)

        if sensitive:
            label = QLabel(
                "The key shown above is private. "
                "Clear the clipboard after use."
            )
            label.setWordWrap(True)
            label.setStyleSheet(
                "font-size: 11px; font-weight: bold;"
            )
            self.layout.addWidget(label)

        self.layout.addWidget(back)
        self.layout.addStretch()


    def show_text_qr(
        self,
        title,
        text,
        description,
        sensitive,
        return_callback,
    ):
        self.clear_layout()
        self.resize(650, 800)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            "font-size: 20px; font-weight: bold;"
        )

        description_label = QLabel(description)
        description_label.setWordWrap(True)

        text_label = QLabel(text)
        text_label.setWordWrap(True)
        text_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse
        )
        text_label.setStyleSheet(
            "font-size: 11px; padding: 10px; border: 1px solid gray;"
        )

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)

        qr_path = "signer/text_export.png"
        qr.make_image().convert("RGB").save(qr_path)

        qr_label = QLabel()
        qr_label.setPixmap(
            QPixmap(qr_path).scaled(
                420,
                420,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )
        qr_label.setAlignment(Qt.AlignCenter)

        copy = QPushButton("Copy Text")
        copy.setMinimumHeight(40)
        copy.clicked.connect(
            lambda: self.copy_text(text)
        )

        back = QPushButton("Back")
        back.setMinimumHeight(40)
        back.clicked.connect(return_callback)

        self.layout.addWidget(title_label)
        self.layout.addWidget(description_label)
        self.layout.addWidget(text_label)
        self.layout.addWidget(qr_label)
        self.layout.addWidget(copy)

        if sensitive:
            warning = QLabel(
                "WARNING: This QR code contains sensitive private data."
            )
            warning.setWordWrap(True)
            warning.setStyleSheet(
                "font-size: 11px; font-weight: bold;"
            )
            self.layout.addWidget(warning)

        self.layout.addWidget(back)
        self.layout.addStretch()




    def show_private_key_save_warning(
        self,
        key_text,
        title,
        return_callback,
    ):
        self.clear_layout()
        self.resize(600, 600)

        title_label = QLabel("Save Master Private Key")
        title_label.setStyleSheet(
            "font-size: 22px; font-weight: bold;"
        )

        warning = QLabel(
            "WARNING: THIS FILE WILL CONTAIN YOUR MASTER PRIVATE KEY.\n\n"
            "Anyone who obtains the file may be able to derive the wallet's "
            "private keys and spend funds.\n\n"
            "Only save this file to secure offline storage. "
            "Do not save it to an online computer or cloud storage."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "font-size: 13px; font-weight: bold;"
        )

        save = QPushButton("Save Master Private Key")
        save.setMinimumHeight(42)

        def save_private_key():
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Master Private Key",
                "electrumsvp-master-xprv.txt",
                "Text Files (*.txt);;All Files (*)",
            )

            if not path:
                return

            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(key_text)
            except Exception as e:
                self.show_error(
                    f"Unable to save the master private key:\n\n{e}"
                )
                return

            self.show_key_qr(
                title,
                key_text,
                "WARNING: Anyone with this key can derive the "
                "wallet's private keys and spend funds.\n\n"
                "Do not enter this key into an online device unless "
                "you fully understand the consequences.",
                True,
                return_callback,
            )

        save.clicked.connect(save_private_key)

        cancel = QPushButton("Cancel")
        cancel.setMinimumHeight(42)
        cancel.clicked.connect(
            lambda: self.show_key_qr(
                title,
                key_text,
                "WARNING: Anyone with this key can derive the "
                "wallet's private keys and spend funds.\n\n"
                "Do not enter this key into an online device unless "
                "you fully understand the consequences.",
                True,
                return_callback,
            )
        )

        self.layout.addStretch()
        self.layout.addWidget(title_label)
        self.layout.addSpacing(15)
        self.layout.addWidget(warning)
        self.layout.addSpacing(25)
        self.layout.addWidget(save)
        self.layout.addWidget(cancel)
        self.layout.addStretch()


    # ------------------------------------------------------------------
    # Transaction loading / QR
    # ------------------------------------------------------------------

    def show_load_transaction(self):
        self.clear_layout()
        self.resize(600, 650)

        title = QLabel("Load Transaction")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        instructions = QLabel(
            "Load an unsigned transaction into the signer.\n\n"
            "You can paste transaction data, scan a QR code, "
            "or load it from a file."
        )
        instructions.setWordWrap(True)

        transaction_input = QTextEdit()
        transaction_input.setPlaceholderText("Paste transaction data here...")
        transaction_input.setMinimumHeight(250)

        paste = QPushButton("Load Pasted Transaction")
        paste.setMinimumHeight(42)
        paste.clicked.connect(
            lambda: self.load_pasted_transaction(
                transaction_input.toPlainText()
            )
        )

        scan = QPushButton("Scan QR Code")
        scan.setMinimumHeight(42)
        scan.clicked.connect(self.scan_transaction)

        file_button = QPushButton("Load from File")
        file_button.setMinimumHeight(42)
        file_button.clicked.connect(self.load_transaction)

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(self.show_home)

        self.layout.addWidget(title)
        self.layout.addWidget(instructions)
        self.layout.addWidget(transaction_input)
        self.layout.addWidget(paste)
        self.layout.addWidget(scan)
        self.layout.addWidget(file_button)
        self.layout.addWidget(back)
        self.layout.addStretch()

        transaction_input.setFocus()


    def decode_transaction_qr(self, data):
        data = bitcoin.base_decode(data, length=None, base=43)
        text = gzip.decompress(data).decode() if data.startswith(b"\x1f\x8b") else bh2u(data)
        return Transaction.from_dict(txdict_from_str(text))

    def transaction_from_data(self, data):
        data = data.strip()
        if not data:
            raise ValueError("The transaction data is empty.")

        try:
            possible_json = json.loads(data)
        except json.JSONDecodeError:
            possible_json = None

        if isinstance(possible_json, dict):
            if (
                possible_json.get("protocol") == "electrumsvp-signer"
                and possible_json.get("version") == 1
                and possible_json.get("transaction") is not None
            ):
                tx = Transaction.from_dict(possible_json["transaction"])
                request = json.dumps(possible_json, sort_keys=True, separators=(",", ":"))
                return tx, request
            try:
                tx = Transaction.from_dict(possible_json)
                request = json.dumps(json.loads(create_signing_request(tx.to_dict())), sort_keys=True, separators=(",", ":"))
                return tx, request
            except Exception:
                pass
            try:
                tx = Transaction.from_dict(txdict_from_str(data))
                request = json.dumps(json.loads(create_signing_request(tx.to_dict())), sort_keys=True, separators=(",", ":"))
                return tx, request
            except Exception:
                pass

        try:
            raw = bytes.fromhex(data)
            tx = Transaction.from_bytes(raw)
            request = json.dumps(json.loads(create_signing_request(tx.to_dict())), sort_keys=True, separators=(",", ":"))
            return tx, request
        except Exception:
            pass

        try:
            tx = self.decode_transaction_qr(data)
            request = json.dumps(json.loads(create_signing_request(tx.to_dict())), sort_keys=True, separators=(",", ":"))
            return tx, request
        except Exception:
            pass

        raise ValueError("The transaction data is not in a supported ElectrumSVP transaction format.")

    def load_pasted_transaction(self, data):
        try:
            tx, request = self.transaction_from_data(data)
        except Exception as e:
            self.show_error(f"Unable to load the pasted transaction:\n\n{e}")
            return
        self.show_transaction(tx, request)

    def load_transaction(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Transaction",
            "",
            "Transaction Files (*.json *.txt *.tx *.txn *.hex);;All Files (*)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()
            tx, request = self.transaction_from_data(data)
        except UnicodeDecodeError:
            self.show_error("Unable to read the selected file as text.")
            return
        except Exception as e:
            self.show_error(f"Unable to load the transaction:\n\n{e}")
            return
        self.show_transaction(tx, request)

    def scan_transaction(self):
        result = scan_barcode(max_duration=60)
        if not result:
            self.show_error("No QR code was scanned.")
            return

        tx = None
        request = None
        try:
            possible = json.loads(result)
            if isinstance(possible, dict) and possible.get("protocol") == "electrumsvp-signer" and possible.get("version") == 1 and possible.get("transaction") is not None:
                request = possible
                tx = Transaction.from_dict(possible["transaction"])
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        if tx is None:
            try:
                tx = self.decode_transaction_qr(result)
                request = json.loads(create_signing_request(tx.to_dict()))
            except Exception as e:
                self.show_error(f"Unable to read the transaction QR:\n\n{e}")
                return

        self.show_transaction(tx, json.dumps(request, sort_keys=True, separators=(",", ":")))

    # ------------------------------------------------------------------
    # Transaction review / signing
    # ------------------------------------------------------------------

    def show_transaction(self, tx, signing_request, account_derivation_path=DEFAULT_ACCOUNT_DERIVATION):
        self.clear_layout()
        self.resize(650, 800)
        title = QLabel("Review Transaction")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        print()
        print("TRANSACTION INPUT VALUES:")
        for i, txin in enumerate(tx.inputs):
            print(f"  Input {i}: value={txin.value!r}")
        print()

        total_input = sum(txin.value for txin in tx.inputs)

        total_output = sum(txout.value for txout in tx.outputs)
        fee = total_input - total_output
        fingerprint = transaction_fingerprint(tx)

        details = QLabel(
            f"Inputs: {len(tx.inputs)}\nTotal inputs: {total_input:,} sats\n\n"
            f"Outputs: {len(tx.outputs)}\nTotal outputs: {total_output:,} sats\n\n"
            f"Fee: {fee:,} sats"
        )
        destinations_text = "Destinations:\n"
        for index, txout in enumerate(tx.outputs):
            display_text, _ = tx_output_to_display_text(txout)
            destinations_text += f"\nOutput {index}: {txout.value:,} sats\nTo: {display_text}\n"
        destinations = QLabel(destinations_text)
        destinations.setWordWrap(True)
        destinations.setTextInteractionFlags(
            Qt.TextSelectableByMouse
        )

        destinations_scroll = QScrollArea()
        destinations_scroll.setWidgetResizable(True)
        destinations_scroll.setWidget(destinations)
        destinations_scroll.setMinimumHeight(80)
        destinations_scroll.setMaximumHeight(300)

        fp_title = QLabel("Transaction Fingerprint")
        fp_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        fp = QLabel(fingerprint)
        fp.setWordWrap(True)
        fp.setTextInteractionFlags(Qt.TextSelectableByMouse)

        derivation_title = QLabel("Account Derivation Path")
        derivation_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        derivation_input = QLineEdit(account_derivation_path)
        derivation_input.setMinimumHeight(40)
        suffix = QLabel("+ /0/index or /1/index")
        suffix.setStyleSheet("font-size: 13px; font-weight: bold;")
        row = QHBoxLayout()
        row.addWidget(derivation_input)
        row.addWidget(suffix)
        explanation = QLabel(
            "Enter the account-level path only. The transaction supplies the final branch and address index.\n"
            "Receiving: /0/index\nChange: /1/index"
        )
        explanation.setWordWrap(True)
        explanation.setStyleSheet("font-size: 11px;")

        approve = QPushButton("Approve & Sign")
        approve.setMinimumHeight(42)
        approve.clicked.connect(lambda: self.approve_transaction(tx, signing_request, derivation_input.text()))
        reject = QPushButton("Reject")
        reject.setMinimumHeight(42)
        reject.clicked.connect(self.show_home)

        self.layout.addWidget(title)
        self.layout.addSpacing(12)
        self.layout.addWidget(details)
        self.layout.addWidget(
            destinations_scroll
        )
        self.layout.addSpacing(12)
        self.layout.addWidget(fp_title)
        self.layout.addWidget(fp)
        self.layout.addSpacing(12)
        self.layout.addWidget(derivation_title)
        self.layout.addLayout(row)
        self.layout.addWidget(explanation)
        self.layout.addStretch()
        self.layout.addWidget(approve)
        self.layout.addWidget(reject)

    def approve_transaction(self, tx, signing_request, account_derivation_path):
        path = account_derivation_path.strip()
        try:
            self.parse_derivation_path(path)
        except Exception as e:
            self.show_error(f"Invalid account derivation path:\n\n{e}")
            return
        self.show_approval(tx, signing_request, path)

    def show_approval(self, tx, signing_request, account_derivation_path):
        self.clear_layout()
        self.resize(600, 650)
        title = QLabel("Transaction Approved")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        fingerprint = transaction_fingerprint(tx)
        message = QLabel(
            "The transaction has been approved.\n\n"
            f"Account path:\n{account_derivation_path}\n\n"
            f"Fingerprint:\n{fingerprint}"
        )
        message.setWordWrap(True)
        message.setTextInteractionFlags(Qt.TextSelectableByMouse)
        continue_button = QPushButton("Continue to Signing")
        continue_button.setMinimumHeight(42)
        continue_button.clicked.connect(lambda: self.show_seed_entry(tx, signing_request, fingerprint, account_derivation_path))
        back = QPushButton("Back to Review")
        back.setMinimumHeight(42)
        back.clicked.connect(lambda: self.show_transaction(tx, signing_request, account_derivation_path))
        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addWidget(message)
        self.layout.addSpacing(25)
        self.layout.addWidget(continue_button)
        self.layout.addWidget(back)
        self.layout.addStretch()

    def show_seed_entry(self, tx, signing_request, approved_fingerprint, account_derivation_path):
        self.clear_layout()
        self.resize(600, 600)

        if self.session_mnemonic:
            title = QLabel("Use Session Signing Seed")
            title.setStyleSheet("font-size: 22px; font-weight: bold;")

            instructions = QLabel(
                "A signing seed is currently loaded in memory for this session.\n\n"
                "The signer will use this seed for the transaction.\n\n"
                f"Account derivation path:\n{account_derivation_path}\n\n"
                "The seed is not saved to disk and will be lost when the signer is shut down."
            )
            instructions.setWordWrap(True)

            sign = QPushButton("Sign Transaction")
            sign.setMinimumHeight(42)
            sign.clicked.connect(
                lambda: self.sign_transaction(
                    tx,
                    signing_request,
                    approved_fingerprint,
                    account_derivation_path,
                    self.session_mnemonic,
                )
            )

            different_seed = QPushButton("Use Different Seed")
            different_seed.setMinimumHeight(42)
            different_seed.clicked.connect(
                lambda: self.show_manual_seed_entry(
                    tx,
                    signing_request,
                    approved_fingerprint,
                    account_derivation_path,
                )
            )

            back = QPushButton("Back")
            back.setMinimumHeight(42)
            back.clicked.connect(
                lambda: self.show_approval(
                    tx,
                    signing_request,
                    account_derivation_path,
                )
            )

            self.layout.addStretch()
            self.layout.addWidget(title)
            self.layout.addWidget(instructions)
            self.layout.addSpacing(20)
            self.layout.addWidget(sign)
            self.layout.addWidget(different_seed)
            self.layout.addWidget(back)
            self.layout.addStretch()

            return

        self.show_manual_seed_entry(
            tx,
            signing_request,
            approved_fingerprint,
            account_derivation_path,
        )


    def show_manual_seed_entry(self, tx, signing_request, approved_fingerprint, account_derivation_path):
        self.clear_layout()
        self.resize(600, 600)

        title = QLabel("Enter Signing Seed")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")

        instructions = QLabel(
            "Enter the BIP39 seed for this signer.\n\n"
            "The seed is used only for this signing operation and is not stored.\n\n"
            f"Account derivation path:\n{account_derivation_path}"
        )
        instructions.setWordWrap(True)

        seed_input = QLineEdit()
        seed_input.setPlaceholderText("BIP39 seed")
        seed_input.setEchoMode(QLineEdit.Normal)
        seed_input.setMinimumHeight(32)

        sign = QPushButton("Sign Transaction")
        sign.setMinimumHeight(42)
        sign.clicked.connect(
            lambda: self.sign_transaction(
                tx,
                signing_request,
                approved_fingerprint,
                account_derivation_path,
                seed_input.text(),
            )
        )

        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(
            lambda: self.show_approval(
                tx,
                signing_request,
                account_derivation_path,
            )
        )

        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addWidget(instructions)
        self.layout.addSpacing(18)
        self.layout.addWidget(seed_input)
        self.layout.addWidget(sign)
        self.layout.addWidget(back)
        self.layout.addStretch()

        seed_input.setFocus()


    def sign_transaction(self, tx, signing_request, approved_fingerprint, account_derivation_path, mnemonic):
        mnemonic = mnemonic.strip()

        if not mnemonic:
            self.show_error("No BIP39 seed was entered.")
            return
        try:
            response = sign_approved_transaction(
                tx,
                mnemonic,
                approved_fingerprint,
                account_derivation_path,
            )
            signed_tx = apply_signing_response(
                signing_request,
                response,
            )

            # A multisig transaction may remain incomplete after this
            # signer adds its signature. Verify that the signing operation
            # actually added at least one signature.
            original_tx = Transaction.from_dict(
                tx.to_dict()
            )

            original_signature_count = sum(
                1
                for txin in original_tx.inputs
                for signature in txin.signatures
                if signature != b"\xff"
            )

            signed_signature_count = sum(
                1
                for txin in signed_tx.inputs
                for signature in txin.signatures
                if signature != b"\xff"
            )

            if signed_signature_count <= original_signature_count:
                raise ValueError(
                    "Signer response did not add a valid signature"
                )

            signed_json = json.dumps(
                signed_tx.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            )

            signed_data = base_encode(
                gzip.compress(signed_json.encode("utf-8")),
                base=43,
            )

            signed_hex = signed_tx.to_hex()


        except Exception as e:
            import traceback
            traceback.print_exc()
            self.show_error(f"Signing failed:\n\n{e}")

            return

        self.session_mnemonic = mnemonic
        self.show_signing_result(tx, signed_data, signed_json, signed_hex)


    def show_signing_result(
        self,
        tx,
        signed_transaction_data,
        signed_transaction_json,
        signed_transaction_hex,
    ):
        self.clear_layout()
        self.resize(650, 900)
        title = QLabel("Transaction Signed")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        message = QLabel(
            "The transaction was successfully signed.\n\n"
            "Scan the QR code below with the online wallet, or copy/save the signed transaction below."
        )
        message.setWordWrap(True)

        # ------------------------------------------------------------
        # QR transaction response
        # ------------------------------------------------------------

        # Use a single static QR for smaller payloads.
        # Larger payloads use animated QR transport.
        STATIC_QR_MAX_BYTES = 1200

        if len(signed_transaction_data.encode("utf-8")) <= STATIC_QR_MAX_BYTES:
            frames = [signed_transaction_data]
        else:
            frames = create_frames(signed_transaction_data)


        self.signing_qr_frames = frames
        self.signing_qr_frame_index = 0

        qr_label = QLabel()
        qr_label.setAlignment(Qt.AlignCenter)

        frame_label = QLabel()
        frame_label.setAlignment(Qt.AlignCenter)

        def update_qr_frame():
            frame_data = self.signing_qr_frames[
                self.signing_qr_frame_index
            ]

            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=4,
                border=4,
            )

            qr.add_data(frame_data)
            qr.make(fit=True)

            qr_path = "signer/signing_response.png"

            qr.make_image().convert("RGB").save(qr_path)

            qr_label.setPixmap(
                QPixmap(qr_path).scaled(
                    350,
                    350,
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )

            frame_label.setText(
                "Frame {} of {}".format(
                    self.signing_qr_frame_index + 1,
                    len(self.signing_qr_frames),
                )
            )

        update_qr_frame()

        if len(frames) > 1:

            self.signing_qr_timer = QTimer(self)

            def next_qr_frame():
                self.signing_qr_frame_index = (
                    self.signing_qr_frame_index + 1
                ) % len(self.signing_qr_frames)

                update_qr_frame()

            self.signing_qr_timer.timeout.connect(
                next_qr_frame
            )

            self.signing_qr_timer.start(250)

        fingerprint = QLabel(
            f"Transaction fingerprint:\n{transaction_fingerprint(tx)}"
        )
        fingerprint.setWordWrap(True)
        fingerprint.setTextInteractionFlags(
            Qt.TextSelectableByMouse
        )

        response = QLabel(
            f"QR transaction data\n"
            f"{len(signed_transaction_data.encode('utf-8'))} bytes"
        )
        response.setAlignment(Qt.AlignCenter)
        signed_title = QLabel("Signed Transaction")
        signed_title.setStyleSheet("font-size: 13px; font-weight: bold;")

        signed_input = QTextEdit(signed_transaction_json)
        signed_input.setReadOnly(True)
        signed_input.setMinimumHeight(120)
        signed_input.setMaximumHeight(180)
        signed_input.setStyleSheet("font-size: 10px;")

        copy = QPushButton("Copy Signed Transaction")
        copy.setMinimumHeight(40)
        copy.clicked.connect(
            lambda: self.copy_text(signed_transaction_json)
        )

        save = QPushButton("Save Signed Transaction")
        save.setMinimumHeight(40)
        save.clicked.connect(
            lambda: self.save_signed_transaction(signed_transaction_json)
        )


        home = QPushButton("Return Home")
        home.setMinimumHeight(42)
        home.clicked.connect(self.show_home)
        self.layout.addWidget(title)
        self.layout.addWidget(message)
        self.layout.addWidget(qr_label)
        self.layout.addWidget(frame_label)
        self.layout.addWidget(response)
        self.layout.addWidget(fingerprint)
        self.layout.addWidget(signed_title)
        self.layout.addWidget(signed_input)
        self.layout.addWidget(copy)
        self.layout.addWidget(save)
        self.layout.addStretch()
        self.layout.addWidget(home)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def show_error(self, message):
        self.clear_layout()
        self.resize(500, 500)
        title = QLabel("Error")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        error = QLabel(message)
        error.setWordWrap(True)
        back = QPushButton("Back")
        back.setMinimumHeight(42)
        back.clicked.connect(self.show_home)
        self.layout.addStretch()
        self.layout.addWidget(title)
        self.layout.addSpacing(15)
        self.layout.addWidget(error)
        self.layout.addSpacing(25)
        self.layout.addWidget(back)
        self.layout.addStretch()


def main():
    app = QApplication(sys.argv)

    app.setApplicationName("electrumsvp-signer")
    app.setApplicationDisplayName(
        f"ElectrumSVP Signer {__version__}"
    )
    app.setDesktopFileName("electrumsvp-signer.desktop")

    icon_path = os.path.join(
        os.path.dirname(__file__),
        "electrumsvp-signer-icon.png",
    )

    app.setWindowIcon(QIcon(icon_path))

    app.setStyleSheet(
        DARK_THEME
        + """
    QSpinBox::up-button,
    QSpinBox::down-button {
        width: 20px;
    }

    QSpinBox::up-button {
        subcontrol-origin: border;
        subcontrol-position: top right;
    }

    QSpinBox::down-button {
        subcontrol-origin: border;
        subcontrol-position: bottom right;
    }
    """
    )


    window = SignerWindow()
    window.setWindowIcon(QIcon(icon_path))
    window.show()

    sys.exit(app.exec_())



if __name__ == "__main__":
    main()


