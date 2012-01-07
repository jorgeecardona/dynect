from setuptools import setup
from os.path import join, abspath, dirname
here = lambda *x: join(abspath(dirname(__file__)), *x)


setup(
    name='dynect',
    version='0.0.1',
    description='Wrapper library to Dynect API.',
    long_description=here('README.rst'),
    author='Jorge Eduardo Cardona',
    author_email='jorgeecardona@gmail.com',
    install_requires=['distribute', 'requests'],
    setup_requires=['unittest2', 'mock', 'requests', 'urllib3'],
    test_suite='tests')
