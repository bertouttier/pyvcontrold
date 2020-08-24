#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pyvcontrold',
    version='0.0.15',
    author='Bert Outtier',
    author_email='outtierbert@gmail.com',
    url='https://github.com/bertouttier/pyvcontrold',
    description='Library Viessmann heaters',
    download_url='https://github.com/bertouttier/pyvcontrold',
    license='MIT',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=['vcontrold'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
        'async-timeout>=3.0.1',
        'pyserial-asyncio>=0.4',
        'scapy>=2.4.3'
    ],
)
