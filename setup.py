import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

__tag__ = ""
__build__ = 0
__version__ = "{}".format(__tag__)

setuptools.setup(
    name="padding-oracle",
    version=__version__,
    author="Denis Vasilìk",
    author_email="security@denisvasilik.com",
    url="https://www.denisvasilik.com",
    project_urls={
        "Bug Tracker": "https://github.com/denisvasilik/padding-oracle/issues/",
        "Source Code": "https://github.com/denisvasilik/padding-oracle/",
    },
    description="Padding Oracle Attack Utilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "Operating System :: OS Independent",
    ],
    dependency_links=[],
    package_dir={"padding_oracle": "padding_oracle"},
    package_data={},
    data_files=[("", ["CHANGELOG.md"])],
    setup_requires=[],
    install_requires=[
        "binalyzer",
    ],
)
