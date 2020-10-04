# Anubis
## Signature Based Anti-Malware Software
When I came to think how Anubis will work, it was obvious that its first version will be able to defend the system using one of two modes:
 
### Reactive mode:
“After incident mode” or “push button mode”. This mode will check if the machine is infected and react immediately by removing the malware artifacts and decrypting files “in case of ransomware”. It follows the same procedure; 1- check a list of IOCs. 2-if the machine is infected = use the appropriate removal tool. The only difference is Anubis won’t work unless it’s told to work. Thus, making a lot of responsibility on the human factor. 

### Proactive mode (Further work):
In this mode -before any attack happens- Anubis will monitor network connections, downloaded files, registry keys or it can take feed from monitoring tools like sysmon or IDS softwares and compare the data with the list of IOCs. If any matching happens, the corresponding removal tool for the detected malware will be launched as real-time protection, As Anubis is taking the standby stance waiting for any compromise.
I’ve decided to delay this feature for now and make it  available in Anubis 2.
 

