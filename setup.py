from setuptools import setup, find_namespace_packages

includes = [
    "package_nso_to_oc",
    "package_nso_to_oc.*"
]

setup(
    name='nso-oc',
    version='0.0.1',
    package_dir={'package_nso_to_oc': 'package_nso_to_oc'},
    packages=find_namespace_packages(
        include=includes
    ),
    description='Cisco NSO OpenConfig Tools',
    install_requires=[
        'urllib3',
        'importlib-metadata; python_version == "3.8"',
    ],
    entry_points='''
        [console_scripts]
        nso-oc=package_nso_to_oc.main:main
    ''',
)