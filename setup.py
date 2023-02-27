from setuptools import setup, find_namespace_packages
from os import environ
from pathlib import Path
from packaging.version import Version

includes = [
    "package_nso_to_oc",
    "package_nso_to_oc.*",
]

this_directory = Path(__file__).parent
long_description = (this_directory / "package_nso_to_oc" / "README.md").read_text()

version_string = environ.get("RELEASE_VERSION", "0.0.0.dev0")
version = Version(version_string)

setup(
    name='nso-oc',
    version=str(version),
    package_dir={'package_nso_to_oc': 'package_nso_to_oc'},
    packages=find_namespace_packages(
        include=includes
    ),
    description='Cisco NSO OpenConfig Tools',
    install_requires=[
        'urllib3',
    ],
    entry_points='''
        [console_scripts]
        nso-oc=package_nso_to_oc.main:main
    ''',
    long_description=long_description,
    long_description_content_type='text/markdown',
    include_package_data=True,
)