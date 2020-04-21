import psutil
import re
import os
import tempfile
import winreg
import sys
 
def remove(path):
    path = path.replace("\\", "/")
    os.remove(path)
    print("File at {} was deleted".format(path))
 
 
def deleteRegistry(regKey, regSubkey, malFile):
    hKey = winreg.OpenKey(regKey, regSubkey, 0, winreg.KEY_ALL_ACCESS)
    i = 0
    while True:
        try:
            x = winreg.EnumValue(hKey, i)
            value = str(x[0])
            data = str(x[1])
            if malFile in data:
                print("Found Malware registry value")
                winreg.DeleteValue(hKey, value)
                print("Deleted Malware registry value")
                break
            i += 1
        except:
            break
    winreg.CloseKey(hKey)
   
 
is32bit = 1
if sys.maxsize > 2**32:
    is32bit = 0
 
malFile = ""
malProcess = ""
if is32bit:
    malProcess = "wuauclt.exe"
else:
    malProcess = "svchost.exe"
tempDir = tempfile.gettempdir()
 
 
for proc in psutil.pids():
    p = psutil.Process(proc)
    if(p.name() == malProcess):
        try:
            files = p.open_files()
        except:     #can't open process files
            continue
        for f in files:
            if tempDir in f[0]:
                x = f[0].split('\\')
                if(x[-1][0:2] == "ms"):
                    malFile = x[-1]
                    print("Malware random name is: {}".format(malFile))
                    try:
                        p.kill()
                        print("Malware Process with PID {} was killed".format(proc))
                    except:
                        print("Unable to kill the process")
                        exit(1)
 
if not malFile: exit(0)
remove(os.path.join(tempDir, malFile))
 
key1 = winreg.HKEY_CURRENT_USER
sub1 = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
 
key2 = winreg.HKEY_LOCAL_MACHINE
sub2 = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
 
deleteRegistry(key1, sub1, malFile)
deleteRegistry(key2, sub2, malFile)
