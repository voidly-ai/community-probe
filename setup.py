from setuptools import setup

setup(
    name="voidly-probe",
    version="1.0.6",
    description="Voidly Community Probe — Help measure internet censorship worldwide",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Voidly",
    author_email="team@voidly.ai",
    url="https://github.com/voidly-ai/community-probe",
    project_urls={
        "Homepage": "https://voidly.ai/probes",
        "Documentation": "https://voidly.ai/api-docs",
        "Source": "https://github.com/voidly-ai/community-probe",
        "Bug Tracker": "https://github.com/voidly-ai/community-probe/issues",
    },
    py_modules=["voidly_probe"],
    python_requires=">=3.8",
    install_requires=[],  # Zero external dependencies
    entry_points={
        "console_scripts": [
            "voidly-probe=voidly_probe:main",
        ],
    },
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Scientific/Engineering",
    ],
    keywords="censorship internet-freedom probe network-measurement ooni",
)
