"""Setup configuration for the Security Hardening Tool."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="security-hardening-tool",
    version="1.0.0",
    author="Security Hardening Team",
    author_email="security@example.com",
    description="Cross-Platform Security Hardening Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/security-hardening-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "security-hardening=security_hardening_tool.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "security_hardening_tool": [
            "config/*.yaml",
            "config/*.json",
            "templates/*.html",
            "templates/*.xml",
        ],
    },
)