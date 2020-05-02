import sys
from functools import partial
from PIL import Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import sha1
from random import seed, sample, randint
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QPlainTextEdit, QFileDialog, QTabWidget,
                             QScrollArea, QTextEdit)
import traceback








class Model(object):
    def __init__(self):
        self.enc_img_path = None
        self.dec_img_path = None

    def set_img(self, mode, path):
        if mode == "e":
            self.enc_img_path = path
        else:
            self.dec_img_path = path

    def get_real_key(self, key):
        key_coded = key.encode()
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = b"\xcd^q\x19\x16\xcc}\x10\xf0\x17=\xdf\x95\x19\xb9-",
            iterations = 100_000,
            backend = default_backend()
        )
        real_key = urlsafe_b64encode(kdf.derive(key_coded))
        return real_key

    def encrypt_message(self, key, message):
        message_coded = message.encode()
        real_key = self.get_real_key(key)
        fern = Fernet(real_key)
        enc_message = fern.encrypt(message_coded)
        return enc_message

    def decrypt_message(self, key, enc_message):
        real_key = self.get_real_key(key)
        fern = Fernet(real_key)
        try:
            message = fern.decrypt(enc_message).decode()
        except:
            message = "ERROR: INVALID KEY"
        return message

    def generate_img(self, save_file, key, message):
        try:
            og_dot = self.enc_img_path.rfind(".")
            if og_dot == -1:
                return "Input image has no extension"
            st_dot = save_file.rfind(".")
            if st_dot == -1:
                save_file += ".png"
            else:
                save_ext = save_file[st_dot:]
                if save_ext != ".png":
                    return "Image must be saved as a png"
            og_img = Image.open(self.enc_img_path)
            bytes_img = bytearray(og_img.tobytes())
            enc_message = self.encrypt_message(key, message)
            enc_message += b"000END000"
            if len(enc_message) * 8 > len(bytes_img):
                return "Message is too long. Use a larger image"
            seed(int(sha1(key.encode()).hexdigest(), 16) % (10 ** 8))
            indices = BTree()
            for char in range(len(enc_message)):
                num_char = enc_message[char]
                dbit = 1
                for pos in range(8):
                    i = randint(0, len(bytes_img)-1)
                    while not indices.insert(i):
                        i = randint(0, len(bytes_img)-1)
                    bit = (num_char & dbit) >> pos
                    if bit == 1: bytes_img[i] |= 1
                    else: bytes_img[i] &= 254
                    dbit = dbit << 1
            stego_img = Image.frombytes(og_img.mode, og_img.size, bytes(bytes_img))
            stego_img.save(save_file)
        except Exception as e:
            traceback.print_exc()
            return "Unable to generate image"
        return "An image has been generated"

    def extract_message(self, key):
        try:
            stego_img = Image.open(self.dec_img_path)
            bytes_img = stego_img.tobytes()
            message = []
            ending = [48, 48, 48, 69, 78, 68, 48, 48, 48]  # "000END000"
            num_char = 0
            pos = 0
            seed(int(sha1(key.encode()).hexdigest(), 16) % (10 ** 8))
            indices = BTree()
            while True:
                i = randint(0, len(bytes_img)-1)
                while not indices.insert(i):
                    i = randint(0, len(bytes_img)-1)
                byte = bytes_img[i]
                lsb = (byte & 1)
                num_char = num_char | (lsb << pos)
                pos += 1
                if pos == 8:
                    message.append(num_char)
                    if message[-len(ending):] == ending:
                        break
                    pos = 0
                    num_char = 0
            message = bytes(message[:-len(ending)])
            message = self.decrypt_message(key, message)
            return message
        except Exception as e:
            traceback.print_exc()
        return "ERROR: UNABLE TO EXTRACT MESSAGE"










class Controller(object):
    def __init__(self, model, view):
        self.model = model
        self.view = view
        self.view.connect_enc_get_img_dialog(self.img_selected)
        self.view.connect_dec_get_img_dialog(self.img_selected)
        self.view.connect_gen_img_dialog(self.generate_img)
        self.view.connect_extract_message_btn(self.extract_message)

    def start(self):
        self.view.show()

    def notify(self, message):
        self._notify = NotificationWindow(self.view, message)

    def img_selected(self, mode, file):
        file_name = file[file.rfind("/")+1:]
        if mode == "e": self.view.set_enc_img_label(file_name)
        else: self.view.set_dec_img_label(file_name)
        self.model.set_img(mode, file)

    def generate_img(self, save_file):
        if not self.model.enc_img_path:
            self.notify("You must select an image")
            return
        key = self.view.get_enc_key()
        message = self.view.get_enc_message()
        if not key or not message:
            self.notify("Key or message missing")
            return
        ret_message = self.model.generate_img(save_file, key, message)
        self.notify(ret_message)

    def extract_message(self):
        if not self.model.dec_img_path:
            self.notify("You must select an image")
            return
        key = self.view.get_dec_key()
        if not key:
            self.notify("Key missing")
            return
        message = self.model.extract_message(key)
        self.view.set_dec_message(message)








class NotificationWindow(QMainWindow):
    def __init__(self, parent, message):
        QMainWindow.__init__(self, parent=parent)
        self.central_widget = QWidget(parent=self)
        self.vlayout = QVBoxLayout(self.central_widget)
        self.setWindowModality(Qt.ApplicationModal)
        self.label = QLabel(message, parent=self.central_widget)
        self.close_btn = QPushButton("Close", parent=self.central_widget)
        self.close_btn.clicked.connect(self.close)
        self.vlayout.addWidget(self.label)
        self.vlayout.addWidget(self.close_btn)
        self.setCentralWidget(self.central_widget)
        self.vlayout.setContentsMargins(20, 10, 20, 20)
        self.setFixedSize(self.central_widget.sizeHint())
        self.show()










class View(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        WIDTH, HEIGHT = 400, 300
        self.setWindowTitle("Stego")
        self.setFixedSize(WIDTH, HEIGHT)
        self.central_widget = QTabWidget(parent=self)
        self.central_widget.setFixedSize(WIDTH, HEIGHT)

        self.init_encrypt_tab()
        self.init_decrypt_tab()

        self.central_widget.addTab(self.encrypt_tab, "ENCRYPT")
        self.central_widget.addTab(self.decrypt_tab, "DECRYPT")
        self.setCentralWidget(self.central_widget)

    def init_encrypt_tab(self):
        self.encrypt_tab = QWidget(parent=self.central_widget)

        self.enc_get_img_dialog = QFileDialog(parent=self.encrypt_tab)
        self.enc_get_img_dialog.setFileMode(QFileDialog.AnyFile)

        self.enc_img_btn = QPushButton("Select Image", parent=self.encrypt_tab)
        self.enc_img_btn.clicked.connect(self.enc_get_img_dialog.exec_)
        self.enc_img_label = QLabel("No Image Selected", parent=self.encrypt_tab)
        self.enc_img_hlayout = QHBoxLayout()
        self.enc_img_hlayout.addWidget(self.enc_img_btn)
        self.enc_img_hlayout.addWidget(self.enc_img_label)

        self.enc_key_label = QLabel("Key:", parent=self.encrypt_tab)
        self.enc_key_input = QLineEdit(parent=self.encrypt_tab)
        self.enc_key_hlayout = QHBoxLayout()
        self.enc_key_hlayout.addWidget(self.enc_key_label)
        self.enc_key_hlayout.addWidget(self.enc_key_input)

        self.enc_message_label = QLabel("Message:", parent=self.encrypt_tab)
        self.enc_message_text = QPlainTextEdit(parent=self.encrypt_tab)

        self.gen_img_dialog = QFileDialog(parent=self.encrypt_tab)
        self.gen_img_dialog.setAcceptMode(QFileDialog.AcceptSave)
        self.gen_img_btn = QPushButton("Generate Image", parent=self.encrypt_tab)
        # self.gen_img_btn.setObjectName("gen_img_btn")
        self.gen_img_btn.setProperty("class", "test_class")
        self.gen_img_btn.clicked.connect(self.gen_img_dialog.exec_)

        self.enc_tab_vlayout = QVBoxLayout()
        self.enc_tab_vlayout.addLayout(self.enc_img_hlayout)
        self.enc_tab_vlayout.addLayout(self.enc_key_hlayout)
        self.enc_tab_vlayout.addWidget(self.enc_message_label)
        self.enc_tab_vlayout.addWidget(self.enc_message_text)
        self.enc_tab_vlayout.addWidget(self.gen_img_btn)
        self.encrypt_tab.setLayout(self.enc_tab_vlayout)


    def init_decrypt_tab(self):
        self.decrypt_tab = QWidget(parent=self.central_widget)

        self.dec_get_img_dialog = QFileDialog(parent=self.decrypt_tab)
        self.dec_get_img_dialog.setFileMode(QFileDialog.AnyFile)

        self.dec_img_btn = QPushButton("Select Image", parent=self.decrypt_tab)
        self.dec_img_btn.clicked.connect(self.dec_get_img_dialog.exec_)
        self.dec_img_label = QLabel("No Image Selected", parent=self.decrypt_tab)
        self.dec_img_hlayout = QHBoxLayout()
        self.dec_img_hlayout.addWidget(self.dec_img_btn)
        self.dec_img_hlayout.addWidget(self.dec_img_label)

        self.dec_key_label = QLabel("Key:", parent=self.decrypt_tab)
        self.dec_key_input = QLineEdit(parent=self.decrypt_tab)
        self.dec_key_hlayout = QHBoxLayout()
        self.dec_key_hlayout.addWidget(self.dec_key_label)
        self.dec_key_hlayout.addWidget(self.dec_key_input)

        self.dec_message_label = QLabel("Message:", parent=self.decrypt_tab)
        self.dec_message_text = QTextEdit(parent=self.decrypt_tab)
        self.dec_message_text.setReadOnly(True)

        self.extract_message_btn = QPushButton("Extract Message", parent=self.encrypt_tab)
        self.extract_message_btn.setProperty("class", "test_class")

        self.dec_tab_vlayout = QVBoxLayout()
        self.dec_tab_vlayout.addLayout(self.dec_img_hlayout)
        self.dec_tab_vlayout.addLayout(self.dec_key_hlayout)
        self.dec_tab_vlayout.addWidget(self.dec_message_label)
        self.dec_tab_vlayout.addWidget(self.dec_message_text)
        self.dec_tab_vlayout.addWidget(self.extract_message_btn)
        self.decrypt_tab.setLayout(self.dec_tab_vlayout)

    def connect_enc_get_img_dialog(self, func):
        self.enc_get_img_dialog.fileSelected.connect(partial(func, "e"))

    def connect_dec_get_img_dialog(self, func):
        self.dec_get_img_dialog.fileSelected.connect(partial(func, "d"))

    def connect_gen_img_dialog(self, func):
        self.gen_img_dialog.fileSelected.connect(func)

    def connect_extract_message_btn(self, func):
        self.extract_message_btn.clicked.connect(func)

    def get_enc_key(self):
        return self.enc_key_input.text()

    def get_dec_key(self):
        return self.dec_key_input.text()

    def get_enc_message(self):
        return self.enc_message_text.toPlainText()

    def set_enc_img_label(self, text):
        self.enc_img_label.setText(text)
        self.enc_img_label.repaint()

    def set_dec_img_label(self, text):
        self.dec_img_label.setText(text)
        self.dec_img_label.repaint()

    def set_dec_message(self, message):
        self.dec_message_text.setText(message)
        self.dec_message_text.repaint()











class BTree:

    class Node:
        def __init__(self, val):
            self.left = None
            self.right = None
            self.val = val


    def __init__(self):
        self.root = None

    def insert(self, val):
        if not self.root:
            self.root = self.Node(val)
            return True
        else:
            return self._insert(val, self.root)

    def _insert(self, val, node):
        if val < node.val:
            if not node.left:
                node.left = self.Node(val)
                return True
            else:
                return self._insert(val, node.left)
        elif val > node.val:
            if not node.right:
                node.right = self.Node(val)
                return True
            else:
                return self._insert(val, node.right)
        else:
            return False

    def print_inorder(self):
        self._print_inorder(self.root)

    def _print_inorder(self, node):
        if node:
            self._print_inorder(node.left)
            print(node.val)
            self._print_inorder(node.right)










def main():
    app = QApplication(sys.argv)
    model = Model()
    view = View()
    # view.setStyleSheet(open("stego.css", "r").read())
    controller = Controller(model, view)
    controller.start()
    sys.exit(app.exec())




if __name__ == "__main__":
    main()
