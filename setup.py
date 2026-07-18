#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="threat-digest",
    version="0.1.0",
    description="Threat intelligence digest tool with RAG pipeline",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.11",
    install_requires=[
        "sentence-transformers==3.3.1",
        "faiss-cpu==1.9.0",
        "numpy==1.26.4",
    ],
)
