import re
import ast
from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('mac_generator_validator/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

requirements = [
    'aiofiles==22.1.0',
    'aiohttp==3.8.3',
    'requests==2.28.1',

]

setup(
    name='MacGenerator-Validator',
    version=version,
    description="A simple but effective mac address generator and validator ",
    long_description=readme,
    author="boxxello",
    author_email='francesco.boxxo@gmail.com',
    url='https://github.com/boxxello/MacGenerator-Validator',
    packages=find_packages(),
    package_dir={},
    entry_points={
        'console_scripts': [
            'mac_generator_validator=mac_generator_validator:__main__:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="Apache Software License",
    platforms='any',
    zip_safe=False,
    keywords=['mac', 'generator', 'validator'],
    classifiers=[
        'Development Status :: 0.1.0 - Beta',
        'Intended Audience :: Developers',
        'Environment :: Console',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
