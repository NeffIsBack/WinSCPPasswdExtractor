# WinSCP Password Extractor
WinSCP stores ssh session passwords in an encoded format in either the registry or a config file called WinSCP.ini.

This python script searches in the WinSCP default locations to extract stored credentials for the current user, when executed locally on the target. If a WinSCP.ini config file is already present the script can decode stored credentials as seen below. To gather WinSCP credentials from a remote target or a range of targets there is a module present for the pentesting Tool [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) called "winscp_dump".

These default locations are:
- registry
- %APPDATA%\WinSCP.ini
- %USER%\Documents\WinSCP.ini

## Installation
WinSCPPasswdExtractor is available on pypi.org. Therefore it is recommended to install this tool with pipx:
```python3
pipx install WinSCPPasswdExtractor
```
Alternatively you could install it with pip or simply download the file and run it.

## Usage
You can either specify a file path if you know the exact path to an existing WinSCP.ini file or you let the tool itself look if any credentials are stored in the default locations.

With pipx:
```python3
WinSCPPasswdExtractor
WinSCPPasswdExtractor <path-to-winscp-file>
```

Manually downloaded:
```python3
python WinSCPPasswdExtractor.py
python WinSCPPasswdExtractor.py <path-to-winscp-file>
```

## About
This Tool is based on the work of [winscppasswd](https://github.com/anoopengineer/winscppasswd), the ruby winscp parser from [Metasploit-Framework](https://github.com/rapid7/metasploit-framework) and the awesome work from [winscppassword](https://github.com/dzxs/winscppassword).

They did the hard stuff
