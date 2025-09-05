from setuptools import setup, find_packages

setup(
    name="hwatlib",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "paramiko",
        "python-nmap"
    ],
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
            "hwat-recon=recon:main",
            "hwat-web=web:main",
            "hwat-exploit=exploit:main",
            "hwat-post=post_exploit:main",
        ],
    },
)
