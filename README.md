# buildpki-certgen-tool
# Tool: buildpki for generating CAs by python3 (vault - Hashicorp)

Foobar is a Python library for dealing with word pluralization.

## Installation
Download the file or go git clone to local machine:

## Usage
Run the tool:
```bash
$ python buildpki.py -config file_config.txt
```
you need to provide the config file with format like:
```file
PKI/Path|allowed_domains|common_name|[expiring (hours)]
```
per each line
The TTL option has to be mandatory assigned for root CA, and can be omitted for "child". Make sure that the TTL will be assign for "parent" or root available before running it for "child" 

Additional modules might be required to install too:

```python
import argparse
from datetime import datetime
import hvac  # this IS NOT installed by default
import os

```
There is also the option as running the tool without real modification:
```bash
$ python buildpki.py -config file_config.txt --dry-run
```
It will allow you to run the tool which will just inform you what will be done

use keys "-h" or "--help" to get help for the options for "buildpki":
```bash
$ python buildpki.py --help
```

## Contributing
There is closed repository for now

THANK YOU!

## License
Not yet