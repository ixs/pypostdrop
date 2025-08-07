# setup.py
from setuptools import setup, find_packages

setup(
    name='postdrop',
    version='0.2.0',
    description='Inject mail into Postfix via cleanup socket',
    author='Andreas Thienemann',
    author_email='andreas@bawue.net',
    url='https://github.com/ixs/postdrop',
    license='GPLv3+',
    packages=find_packages(),
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'pypostdrop=postdrop.cli:main',
        ],
    },
)
