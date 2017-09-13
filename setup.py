from distutils.core import setup
import yara_validator

setup(
    name = 'yara_validator',
    packages = ['yara_validator'],
    version = 'v0.1b',  # Ideally should be same as your GitHub release tag varsion
    description = 'A simple library to check yara rules syntax',
    author = 'CIRCL - edhoedt',
    author_email = 'edhoedt@gmail.com',
    license = 'GPLv3',
    url = 'https://github.com/CIRCL/yara-validator',
    download_url = 'https://github.com/CIRCL/yara-validator/archive/v0.1.tar.gz',
    install_requires=[
    	'yara-python',
	'six',
    ],
    keywords = ['yara'],
    classifiers = [],
)
