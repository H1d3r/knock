from setuptools import find_packages, setup
import os

HERE = os.path.abspath(os.path.dirname(__file__))


def load_requirements(path: str) -> list[str]:
    """Load requirements from a local file.

    Must work under PEP 517 isolated builds (wheel-from-sdist), so resolve the
    path relative to this file and fail gracefully if the file isn't present.
    """
    req_path = os.path.join(HERE, path)
    try:
        with open(req_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []

wordlist = 'wordlist' + os.sep + 'wordlist.txt'

setup(
    name='knock-subdomains',
    version='9.0.0',
    description='Knockpy Subdomains Scan',
    url='https://github.com/guelfoweb/knockpy',
    author='Gianni Amato',
    author_email='guelfoweb@gmail.com',
    license='GPL-3.0',
    packages=find_packages(include=["knockpy", "knockpy.*"]),
    package_data={"knockpy": [wordlist]},
    include_package_data=True,
    install_requires=load_requirements("requirements.txt"),
    entry_points={
        'console_scripts': [
            'knockpy=knockpy.knockpy:main',
        ],
    }
)
