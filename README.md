# recursive-virustotal
Recursively calculates the hash of all files in a given path and checks them against the Virustotal threat database.
This script can be used in many different scenarios. The scripts , after calculating the hash of individual files (malware files) and copying/pasting into VirusTotal
and then extract an output inn json format for each malware  , that is written in the log.txt file. 
A detailed description and how to set up and use the script can be found on the blog] (https://fabian-voith.de/2021/02/04/script-to-check-virustotal-for-many-files-and-folders/)

*Update 13/03/2021:* The VirusTotal API module used in this script can be installed via
> pip install virustotal-api
> 
*Update 09/04/2021:* The YAML parser used in this script can be installed via
> pip install PyYAML

A user kindly pointed out that there was a wrong reference in the documentation on my website. This is now fixed; if the script did not run before because of a "ModuleNotFoundError" you might want to try again with the updated installation instructions.

usage: recursive-vt.py [-h] [-p PATH] [-a ALERTLV] [-r recursive]
