# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

from setuptools import setup, find_packages


def get_long_description():
    long_description = open('README.md').read()
    try:
        import subprocess
        import pandoc

        process = subprocess.Popen(
            ['which pandoc'],
            shell=True,
            stdout=subprocess.PIPE,
            universal_newlines=True)

        pandoc_path = process.communicate()[0]
        pandoc_path = pandoc_path.strip('\n')

        pandoc.core.PANDOC_PATH = pandoc_path

        doc = pandoc.Document()
        doc.markdown = long_description
        long_description = doc.rst
    except:
        print("Could not find pandoc or convert properly")
        print("  make sure you have pandoc (system) and pyandoc (python module) installed")

    return long_description

setup(
  name='bgapi',
  version='0.1',
  description='Interface library for the BlueGiga BLE modules',
  long_description=get_long_description(),
  url='https://github.com/mjbrown/bgapi',
  author="Michael Brown",
  author_email="mjbrown.droid@gmail.com",
  packages=find_packages(),
  install_requires=open('requirements.txt').read().split(),
  classifiers=[
      "Development Status :: 3 - Alpha",
      "Intended Audience :: Developers",
      "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      "Programming Language :: Python :: 2.6",
      "Programming Language :: Python :: 2.7",
      "Topic :: Software Development :: Libraries",
      "Operating System :: OS Independent",
  ],
)
