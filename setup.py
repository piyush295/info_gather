from setuptools import setup, find_packages

setup(
    name="info_gather",
    version="1.0.0",
    description="All-in-One Information Gathering Tool",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "argparse",
        "whois",
        "dnspython",
        "requests",
        "shodan",
        "ipwhois",
    ],
    entry_points={
        "console_scripts": [
            "info-gather = info_gather:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
