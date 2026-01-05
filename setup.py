from setuptools import setup, find_packages

setup(
    name="hwatlib",
    version="0.2.0",
    package_dir={"": "hwatlib"},
    packages=find_packages(where="hwatlib"),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "paramiko",
        "python-nmap"
    ],
    extras_require={
        "dev": ["pytest"],
        "async": ["aiohttp"],
        "dns": ["dnspython"],
    },
    author="HwatSauce",
    author_email="muhammadabdullah8040@gmail.com",
    description="A practical penetration testing wrapper library for recon, web, exploitation, and post-exploitation.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/iabdullah215/hwatlib",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires='>=3.7',
    entry_points={
        "console_scripts": [
            "hwat=hwatlib.cli:main",
            "hwat-recon=hwatlib.recon:main",
            "hwat-web=hwatlib.web:main",
            "hwat-exploit=hwatlib.exploit:main",
            "hwat-post=hwatlib.privesc:main",
        ],
    },
)
