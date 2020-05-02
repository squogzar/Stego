from setuptools import setup


APP = ["Stego.py"]

OPTIONS = {
    "iconfile": "images/stego_icon.icns"
}

setup(
    app = APP,
    options = {"py2app": OPTIONS},
    setup_requires = ["py2app"]
)
