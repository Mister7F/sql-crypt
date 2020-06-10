import pathlib
from setuptools import setup

# python setup.py sdist bdist_wheel && twine upload dist/*

README = (pathlib.Path(__file__).parent / "readme.md").read_text()

setup(
    name="SQLCrypt",
    version="0.0.1",
    description="Protect your SQLite database with AES !",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Mister7F/sqlcrypt",
    author="Mister7F",
    author_email="mister7f@gmail.com",
    license="MIT",
    install_requires=["apsw", "pycryptodome"],
)
