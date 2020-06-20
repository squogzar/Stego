from setuptools import setup

APP = ["stego.py"]
NAME = "Stego"

OPTIONS = {
    "iconfile": "images/stego_icon.icns"
}

setup(
    app = APP,
    name = Name,
    options = {"py2app": OPTIONS},
    setup_requires = ["py2app"]
)
