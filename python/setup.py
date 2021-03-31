#!/usr/bin/env python3

from setuptools import setup

setup(
    name = 'ad_gmsa',
    version = '0.0.1',
    description = 'Update Kerberos keytabs based on Microsoft Active Directory group managed service accounts',
    packages = [ 'ad_gmsa' ],
    setup_requires = [ 'wheel' ],
    install_requires = [ ],
    entry_points = {
        'console_scripts': [
            'ad_gmsa_update_keytabs=ad_gmsa.update_keytabs:main',
        ]
    },
)
