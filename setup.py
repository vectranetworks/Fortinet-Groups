from setuptools import setup

setup(
    name='fortinet-groups',
    description='Fortinet Firewall Cognito Integration',
    version='1.0',
    packages=['fortinet-groups'],
    install_requires=['requests', 'pyfortiapi'],
)