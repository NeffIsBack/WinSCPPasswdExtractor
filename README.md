# WinSCP Password Extractor
WinSCP stores ssh session passwords in an encoded format in either the registry or a file called WinSCP.ini.
This python script searches in the winscp default locations to extract stored credentials.

These default file locations are:
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
