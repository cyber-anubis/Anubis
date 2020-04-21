import psutil
import re
import os
import tempfile
import winreg
import signal
 
def remove(path):
    print("File at {} was deleted".format(path))
    path = path.replace("\\", "/")
    os.remove(path)
 
def deleteFiles():
    tempDir = tempfile.gettempdir()
    for file in os.listdir(tempDir):
        if re.search("File(\d)+.jar", file) or re.search("JNativeHook_(\d)+.dll", file):
            d = os.path.join(tempDir,file)
            remove(d)
 
def deleteRegistry():
    regKey = r"Software\Microsoft\Windows\CurrentVersion\Run"
    regValue = "File"
 
    hKey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, regKey, 0, winreg.KEY_ALL_ACCESS)
    i = 0
    while True:
        try:
            if regValue == winreg.EnumValue(hKey, i)[0]:
                print("Found Malware registry value")
                winreg.DeleteValue(hKey, regValue)
                print("Deleted Malware registry value")
                break
            i += 1
        except:
            break
    winreg.CloseKey(hKey)
 
 
for proc in psutil.pids():
    try:
        p = psutil.Process(proc)
        try:
            files = p.open_files()
            for f in files:
                if re.search("File(\d)+.jar", f.path):
                    try:
                        p.kill()
                        print("Malware Process with PID {} was killed".format(proc))
                    except:
                        print("Unable to kill the process")
                        exit(1)
        except:     #Access denied
            continue
    except: #No process with PID
        continue
 
deleteFiles()
deleteRegistry()
