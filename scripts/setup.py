#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name = 'PrimWatch HealthCheck',
    version = '1.0.0',
    description = 'Server health check script for PrimWatch',
    author = 'jimo1001',
    author_email = 'jimo1001@gmail.com',
    license = 'MIT',
    url = 'https://github.com/potix/PrimWatch/wiki',
    packages = find_packages(exclude=['*.tests']),
    zip_safe = True,
    entry_points = """
        [console_scripts]
        healthchecker = healthcheck.healthcheck:main
    """,
)