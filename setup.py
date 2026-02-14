from setuptools import find_packages, setup
import os

def load_requirements(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

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
            'knockpy.py=knockpy.knockpy:main',
        ],
    }
)
