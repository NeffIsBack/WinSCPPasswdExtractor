# WinSCP Password Extractor
This python script tries to gather all credentials stored on the current Windows System.

## Usage
You can either specify a file path if you know the exact path to an existing WinSCP.ini file or you let the tool itself look if any credentials are stored in the default locations.
```python3
winscp.py
winscp.py <path-to-file>
```

## About
This Tool is based on the work of [winscppasswd](https://github.com/anoopengineer/winscppasswd), the ruby winscp parser from [Metasploit-Framework](https://github.com/rapid7/metasploit-framework) and the awesome work from [winscppassword](https://github.com/dzxs/winscppassword)
They did the hard stuff
