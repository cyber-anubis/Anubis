import csv
import os
import hashlib
import winreg

IOCS_DIR = "IOCs"
REMOVAL_TOOLS_DIR = "RemovalTools"

BUF_SIZE = 65536
IOCS = []

###############################################################################################################

def malwareAlert(malware_name, message):
	print(f"[+] {malware_name} {message} detected!")
	print("[+] Removing malware artifacts...")
	
	removalToolName = list(filter(lambda file: malware_name in file, os.listdir(folder)))[0]
	removalTool = os.path.join(REMOVAL_TOOLS_DIR, removalToolName)
	os.system(f"cmd /c {removalTool}")

###############################################################################################################

def hashFile(file_path):
	sha256 = hashlib.sha256()
	with open(file_path, 'rb') as f:
		while True:
			data = f.read(BUF_SIZE)
			if not data:
				break
			sha256.update(data)
	return sha256.hexdigest()


def lookForHashes(ioc_hashes):
	home = os.path.expanduser('~')	# traverse user_path only (just for POC)
	for root, dirs, files in os.walk(home):
		for file in files:
			file_path = os.path.join(root, file)
			file_hash = hashFile(file_path)
			for IOC in IOCS:
				if file_hash in IOC['hashes']:
					malwareAlert(IOC['malware_name'], 'Hash')

###############################################################################################################

def lookForFiles(ioc_files):
	for IOC in IOCS:
		for file in IOC['files']:
			if os.path.isfile(file):
				malwareAlert(IOC['malware_name'], 'File')

###############################################################################################################

def lookForRegistry(ioc_registry):
	for IOC in IOCS:
		for reg in IOC['registry']:
			regKey = "\\".join(reg.split('\\')[:-1])
			regValue = reg.split('\\')[-1]
			hKey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, regKey, 0, winreg.KEY_ALL_ACCESS)
			i = 0
			while True:
				try:
					if regValue == winreg.EnumValue(hKey, i)[0]:
						malwareAlert('Registry')
						break
					i += 1
				except:
					break
			winreg.CloseKey(hKey)

###############################################################################################################

def buildIOC(IOC_file):
	hashes   = []
	files    = []
	registry = [] 
	domains  = []

	with open(IOC_file) as file:
		IOC = csv.reader(file, delimiter=',')
		next(IOC)	# skip header row
		for row in IOC:
			ioc_type, ioc_data = row

			if ioc_type == 'hash':
				hashes.append(ioc_data)
			elif ioc_type == 'file':
				files.append(ioc_data)
			elif ioc_type == 'registry':
				registry.append(ioc_data)
			elif ioc_type == 'domain':	# proactive mode only
				domains.append(ioc_data)

	return {
		"malware_name": IOC_file[:-4],
		"hashes": hashes,
		"files": files,
		"registry": registry,
		"domains": domains
	}

###############################################################################################################

def main():
	for root, dirs, files in os.walk('IOCs'):
		for file in files:
			IOC_file = os.path.join(root, file)
			IOCS.append(buildIOC(IOC_file))
	
	lookForHashes()
	lookForFiles()
	lookForRegistry()

if __name__ == '__main__':
	main()

