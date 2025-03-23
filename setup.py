from setuptools import setup, find_packages

setup(
    name="phantomwatch",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "yara-python",
        "click",
        "rich",
        "argparse",
        "python-dotenv",
        "loguru",
        "requests",
        "yara-python",
        "pySigma",
        "pySigma-backend-elasticsearch",
        "sigmatools",
        "elasticsearch",
        "pyyaml",
        "shodan",
        "OTXv2",
        "tqdm",
        "tabulate",
        "psutil",
    ],
    entry_points={
        "console_scripts": [
            "phantomwatch=phantomwatch.cli.main:main",  # Adjust path if necessary
        ],
    },
    include_package_data=True,
    description="A powerful security tool for everything SOC.",
    author="Ayomiposi Ayoola",
    author_email="posiayoola102@gmail.com",
    url="",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Unix", "linux",
    ],
    python_requires=">=3.6",
)
