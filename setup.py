from setuptools import setup, find_packages

setup(
    name='Cryptode',
    version='1.0.0',
    author='Arya Praneil Pritesh',
    author_email='aryapraneil@gmail.com',
    description='A cryptography framework with 50+ algorithms',
    py_modules=['src.cryptode'],
    install_requires=[
        'argon2-cffi==21.3.0',
        'argon2-cffi-bindings==21.2.0',
        'dependency3<0.5.0',
        'cffi==1.15.1',
        'pywin32==305',
        'pywin32-ctypes==0.2.0',
        'bcrypt==4.0.1',
        'numpy==1.22.1',
    ],
)