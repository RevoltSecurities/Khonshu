from setuptools import setup, find_packages

setup(
    name='Khonshu',
    version='1.0.1',
    author='D. Sanjai Kumar',
    author_email='bughunterz0047@gmail.com',
    description='Khonshu - A powerful port scanning tool written in python that detect open ports with concurrent and accurately',
    packages=find_packages(),
    install_requires=[
        'aiodns==3.1.1',
        'aiofiles==23.2.1',
        'aioping==0.4.0',
        'alive_progress==3.1.4',
        'art==6.1',
        'colorama==0.4.6',
        'Requests==2.31.0',
        'urllib3==1.26.18',
    ],
    entry_points={
        'console_scripts': [
            'khonshu =khonshu.khonshu:main'
        ]
    },
)
