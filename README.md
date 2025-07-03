![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/al3x_n3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)
# WinSCP Password Extractor
WinSCP stores ssh session passwords in an encoded format in either the registry or a config file called WinSCP.ini.

This python script searches in the WinSCP default locations to extract stored credentials for the current user, when executed locally on the target. If a WinSCP.ini config file is already present the script can decode stored credentials as seen below. To gather WinSCP credentials from a remote target or a range of targets there is a module present for the pentesting Tool [NetExec](https://github.com/Pennyw0rth/NetExec) called "winscp".

These default locations are:
- registry
- %APPDATA%\WinSCP.ini
- %USER%\Documents\WinSCP.ini

Alternatively, a registry hive can be decrypted locally if it has been exported from the target (`NTUSER.DAT` file from the user home folder).

## Installation
WinSCPPasswdExtractor is available on pypi.org. Therefore it is recommended to install this tool with pipx:
```python3
pipx install WinSCPPasswdExtractor
```
Alternatively you could install it with pip or simply download the file and run it.

## Usage
You can either specify a file path if you know the exact path to an existing WinSCP.ini file or you let the tool itself look if any credentials are stored in the default locations. If the provided file is a recovered registry hive, pass the `-r` or `--registry` flag.

With pipx:
```python3
WinSCPPasswdExtractor
WinSCPPasswdExtractor <path-to-winscp-file>
WinSCPPasswdExtractor --registry <path-to-ntuser-hive-file>
```

Manually downloaded:
```python3
python WinSCPPasswdExtractor.py
python WinSCPPasswdExtractor.py <path-to-winscp-file>
python WinSCPPasswdExtractor.py --registry <path-to-ntuser-hive-file>

```

## About
This Tool is based on the work of [winscppasswd](https://github.com/anoopengineer/winscppasswd), the ruby winscp parser from [Metasploit-Framework](https://github.com/rapid7/metasploit-framework) and the awesome work from [winscppassword](https://github.com/dzxs/winscppassword).

They did the hard stuff
