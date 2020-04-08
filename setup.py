from setuptools import setup, find_packages

setup(
    name = 'fortinet-groups',
    description = 'Fortinet Firewall & Cognito Integration Script',
    version='1.0',
    url='https://github.com/vectranetworks',
    keywords="vectra cognito fortinet",
    license="MIT",
    packages=find_packages(),
    install_requires=['requests>=2', 'pyfortiapi'],
    classifiers=['License :: OSI Approved :: MIT License', 'Programming Language :: Python :: 3']
)
