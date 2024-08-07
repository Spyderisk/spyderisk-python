# setup.py

from setuptools import setup, find_packages

setup(
    name="spyderisk",
    version="0.1.0",
    author="Stephen Philips",
    author_email="S.C.Phillips@soton.ac.uk",
    description="A description of your project",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Spyderisk/system-modeller",
    packages=find_packages(),
    install_requires=[
        'rdflib>=6.0.2',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
)

