# coding: utf-8
 
__author__ = 'Fabian Voith'
__email__ = 'admin@fabian-voith.de'
__author__ = 'Roberto Bruzzese'
__email__ = 'bruzzese.953247@studenti.uniroma1.it'
######################### e103ae026aa10ff158a37e3d037df740ec745ab78fe3d06f0069eac47d9bb4f1
# 0d16bcf91b67b5bcfd597e2ccb3885c52b5f4e2f3a9bb04824727b8765bbd422
# 42d356e4383af8b10e211d33855a29bbe38980e0a0b88dec01d6e496e12a84d2 USA
# 083693e9bf01e54a1a13e49f23060c0905b8df44fb8e768e3602e9ffd502431e usa davide
# 74a6c2edab31a82a9aea93caae72c1dd2512684d8674a85779818b3ad4ee701e proton vpn roberto.bruzzese@icloud.com
# 1d119070bdfb221ac242fb38263d5b059f6417320c684c66ee88b92b5ea2a01c malwarelasapienza proton vp 
# d0b664ca77137e09a779b4a27fb880eb3fab7a3e40fa186c9563d2d459332cb8 topwebmaster2018
# 36f81a6ebf464ddc4b3e20d141ec19cc7cd7f1a401ce8449d69b1cc49bcdffc0 demicheleflor
# 1c563807cc764d4eed08072b12b453ad56c78b5d565a0f05c59ec6d0fbbe6018 romerobarbagianni
# ae0c9ead5d98578322970a58cd8eb9e1532efa46d78fd1c58b0fd74e07e5261e vercingetorigevirginio
# 6a0f733c10d7c099136427e1ddda181f0d18a05676d7b161d9087b0c629a3a60 roberto_brunn
# 7a6cb576e3489237a6dfb4f4ce2e5e7d68acf326400d74f85647806404425e60 florianademichele
# When first running the script, a default config.yaml will be created.
# Adjust config.yaml before using the script a second time.
# Especially the following two values need to be adjusted:
# api_key: *your VT API Key, see: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key *
# file_path: *top folder from where you want to start your scan, e.g. /opt/NetworkMiner_2-6 *
#########################

# YAML module can be installed via pip install PyYAML
import yaml
import sys
import json
import hashlib
import glob
import os
import time
# VT API module can be installed via pip install virustotal-api
from virus_total_apis import PublicApi as VirusTotalPublicApi
import argparse

class simpleFile:
    # simple file object, automatically calculates hash of itself

    def calculate_hash(self, file_name):
        sha256_hash = hashlib.sha256()
        with open(file_name,'rb') as f:
            # Read and update hash string value in blocks of 4K to avoid buffer overflow
            for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)

        return(sha256_hash.hexdigest())
    
    def __init__(self, file_name):
        self.file_name = file_name
        self.hash = self.calculate_hash(file_name)

    def get_hash(self):
        return(self.hash)

    def get_file_name(self):
        return(self.file_name)

class observedEntity:
    # Contains one hash and all file names that share this hash
    # It also holds the raw VirusTotal result and provides distilled threat intel information
    def __init__(self, file, alerting_level):
        self.files = []
        
        self.files.append(file.get_file_name())
        self.hash = file.get_hash()
        self.isMalicious = False
        self.vt_result = ''
        self.positives = 0
        self.total_scanners = 1 # to avoid division by zero error
        self.ALERTING_LEVEL = alerting_level
        self.detected = False 
    #self.result = '' 
         

    def add_file_name(self, file_name):
        # if a file has the identical hash like another observed entity, we just add the file name
        # so that we will poll the VirusTotal result only once.
        self.files.append(file_name)

    def get_file_names(self):
        # returns the array of file names that share the hash and therefore the VirusTotal results.
        return(self.files)

    def get_hash(self):
        # returns the hash of the observed entity, also used for checking against VirusTotal
        return(self.hash)

    def add_virustotal_result(self, result):
        self.vt_result = result

         # Convert json to dictionary:
        json_data = json.loads(json.dumps(result))
        #try:
        if json_data['results']['response_code'] == 1:
                self.total_scanners = json_data['results']['total']
                self.positives = json_data['results']['positives']
                self.scan_date = json_data['results']['scan_date']
                with open('log.txt', 'a') as f:
                    print("\n{"+'"'+"sha1"+'"'": "+'"'+json_data['results']['sha1']+'",',end = ' ',file=f)
                    print('"'+"av_labels"+'"'": "+"[",end = ' ',file=f)
                    
                try:
                    if json_data['results']['scans']['Bkav']['detected'] == True:
                      with open('log.txt', 'a') as f:
                        print('["'+"Bkav"+'"'+", "+'"'+json_data['results']['scans']['Bkav']['result']+'"],',end = ' ',file=f)
                    
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Lionic']['detected'] == True:
                       with open('log.txt', 'a') as f:
                         print('["'+"Lionic"+'"'+", "+'"'+json_data['results']['scans']['Lionic']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")

                try:
                    if json_data['results']['scans']['Elastic']['detected'] == True:
                        with open('log.txt', 'a') as f:
                          print('["'+"Elastic"+'"'+", "+'"'+json_data['results']['scans']['Elastic']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Cylance']['detected'] == True:
                         with open('log.txt', 'a') as f:
                          print('["'+"Cylance"+'"'+", "+'"'+json_data['results']['scans']['Cylance']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['CrowdStrike']['detected'] == True:
                          with open('log.txt', 'a') as f:
                              print('["'+"CrowdStrike"+'"'+", "+'"'+json_data['results']['scans']['CrowdStrike']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['MicroWorld-eScan']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"MicroWorld-eScan"+'"'+",  "+'"'+json_data['results']['scans']['MicroWorld-eScan']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['ALYac']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"ALYac"+'"'+", "+'"'+json_data['results']['scans']['ALYac']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['FireEye']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"FireEye"+'"'+", "+'"'+json_data['results']['scans']['FireEye']['result']+'"],',end = ' ',file=f)
                    f.clos
                except:
                    print("")
                try:
                    if json_data['results']['scans']['CAT-QuickHeal']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"CAT-QuickHeal"+'"'+", "+'"'+json_data['results']['scans']['CAT-QuickHeal']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['K7AntiVirus']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"K7AntiVirus"+'"'+", "+'"'+json_data['results']['scans']['K7AntiVirus']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Alibaba']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"Alibaba"+'"'+", "+'"'+json_data['results']['scans']['Alibaba']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['K7GW']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"K7GW"+'"'+", "+'"'+json_data['results']['scans']['K7GW']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['ClamAV']['detected'] == True:
                        with open('log.txt', 'a') as f:
                          print('["'+"ClamAV"+'"'+", "+'"'+json_data['results']['scans']['ClamAV']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['BitDefenderTheta']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"BitDefenderTheta"+'"'+", "+'"'+json_data['results']['scans']['BitDefenderTheta']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Paloalto']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Paloalto"+'"'+", "+'"'+json_data['results']['scans']['Paloalto']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Cyren']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"Cyren"+'"'+", "+'"'+json_data['results']['scans']['Cyren']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Symantec']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Symantec"+'"'+", "+'"'+json_data['results']['scans']['Symantec']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['ESET-NOD32']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"ESET-NOD32"+'"'+", "+'"'+json_data['results']['scans']['ESET-NOD32']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['APEX']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"APEX"+'"'+", "+'"'+json_data['results']['scans']['APEX']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['BitDefender']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"BitDefender"+'"'+", "+'"'+json_data['results']['scans']['BitDefender']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['NANO-Antivirus']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"NANO-Antivirus"+'"'+", "+'"'+json_data['results']['scans']['NANO-Antivirus']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['SUPERAntiSpyware']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"SUPERAntiSpyware"+'"'+", "+'"'+json_data['results']['scans']['SUPERAntiSpyware']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['ViRobot']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"ViRobot"+'"'+", "+'"'+json_data['results']['scans']['ViRobot']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['GData']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"GData"+'"'+", "+'"'+json_data['results']['scans']['GData']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Cynet']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"Cynet"+'"'+", "+'"'+json_data['results']['scans']['Cynet']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Ad-Aware']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Ad-Aware"+'"'+", "+'"'+json_data['results']['scans']['Ad-Aware']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Comodo']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Comodo"+'"'+", "+'"'+json_data['results']['scans']['Comodo']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['F-Secure']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"F-Secure"+'"'+", "+'"'+json_data['results']['scans']['F-Secure']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['VIPRE']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"VIPRE"+'"'+", "+'"'+json_data['results']['scans']['VIPRE']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['DrWeb']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"DrWeb"+'"'+", "+'"'+json_data['results']['scans']['DrWeb']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['CMC']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"CMC"+'"'+", "+'"'+json_data['results']['scans']['CMC']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Emisoft']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Emisoft"+'"'+", "+'"'+json_data['results']['scans']['Emisoft']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Sophos']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"Sophos"+'"'+", "+'"'+json_data['results']['scans']['Sophos']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Ikarus']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Ikarus"+'"'+", "+'"'+json_data['results']['scans']['Ikarus']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Jiangmin']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Jiangmin"+'"'+", "+'"'+json_data['results']['scans']['Jiangmin']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['eGambit']['detected'] == True:
                        with open('log.txt', 'a') as f:
                             print('["'+"eGambit"+'"'+", "+'"'+json_data['results']['scans']['eGambit']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Gridinsoft']['detected'] == True:
                       with open('log.txt', 'a') as f:
                           print('["'+"Gridinsoft"+'"'+", "+'"'+json_data['results']['scans']['Gridinsoft']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Arcabit']['detected'] == True:
                         with open('log.txt', 'a') as f:
                          print('["'+"Arcabit"+'"'+", "+'"'+json_data['results']['scans']['Arcabit']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Zillya']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Zillya"+'"'+", "+'"'+json_data['results']['scans']['Zillya']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Sangfor']['detected'] == True:
                        with open('log.txt', 'a') as f:
                          print('["'+"Sangfor"+'"'+", "+'"'+json_data['results']['scans']['Sangfor']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['ZoneAlarm']['detected'] == True:
                     with open('log.txt', 'a') as f:
                        print('["'+"ZoneAlarm"+'"'+", "+'"'+json_data['results']['scans']['ZoneAlarm']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['TACHYON']['detected'] == True:
                         with open('log.txt', 'a') as f:
                             print('["'+"TACHYON"+'"'+", "+'"'+json_data['results']['scans']['TACHYON']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['AhnLab-V3']['detected'] == True:
                        with open('log.txt', 'a') as f:
                          print('["'+"AhnLab-V3"+'"'+", "+'"'+json_data['results']['scans']['AhnLab-V3']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['PUP-XAQ-WF']['detected'] == True:
                     with open('log.txt', 'a') as f:
                        print('["'+"PUP-XAQ-WF"+'"'+", "+'"'+json_data['results']['scans']['PUP-XAQ-WF']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Acronis']['detected'] == True:
                        with open('log.txt', 'a') as f:
                          print('["'+"Acronis"+'"'+", "+'"'+json_data['results']['scans']['Acronis']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['VBA32']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"VBA32"+'"'+", "+'"'+json_data['results']['scans']['VBA32']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['MAX']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"MAX"+'"'+", "+'"'+json_data['results']['scans']['MAX']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Tencent']['detected'] == True:
                     with open('log.txt', 'a') as f:
                        print('["'+"Tencent"+'"'+", "+'"'+json_data['results']['scans']['Tencent']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Zoner']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"Zoner"+'"'+", "+'"'+json_data['results']['scans']['Zoner']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['TrendMicro-HouseCall']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"TrendMicro-HouseCall"+'"'+", "+'"'+json_data['results']['scans']['TrendMicro-HouseCall']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['McAfee-GW-Edition']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"McAfee-GW-Edition"+'"'+", "+'"'+json_data['results']['scans']['McAfee-GW-Edition']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Rising']['detected'] == True:
                      with open('log.txt', 'a') as f:
                        print('["'+"Rising"+'"'+", "+'"'+json_data['results']['scans']['Rising']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Yandex']['detected'] == True:
                     with open('log.txt', 'a') as f:
                        print('["'+"Yandex"+'"'+", "+'"'+json_data['results']['scans']['Yandex']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['SentinelOne']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"SentinelOne"+'"'+", "+'"'+json_data['results']['scans']['SentinelOne']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Avira']['detected'] == True:
                         with open('log.txt', 'a') as f:
                           print('["'+"Avira"+'"'+", "+'"'+json_data['results']['scans']['Avira']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['MAX']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"MAX"+'"'+", "+'"'+json_data['results']['scans']['MAX']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['MaxSecure']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"MaxSecure"+'"'+", "+'"'+json_data['results']['scans']['MaxSecure']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Antiy-AVL']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Antiy-AVL"+'"'+", "+'"'+json_data['results']['scans']['Antiy-AVL']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Fortinet']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Fortinet"+'"'+", "+'"'+json_data['results']['scans']['Fortinet']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Panda']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Panda"+'"'+", "+'"'+json_data['results']['scans']['Panda']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Webroot']['detected'] == True:
                        with open('log.txt', 'a') as f:
                         print('["'+"Webroot"+'"'+", "+'"'+json_data['results']['scans']['Webroot']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Cybereason']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Cybereason"+'"'+", "+'"'+json_data['results']['scans']['Cybereason']['result']+'"],',end = ' ',file=f)
                    f.close
                except:
                    print("")
                try:
                    if json_data['results']['scans']['Qihoo-360']['detected'] == True:
                        with open('log.txt', 'a') as f:
                            print('["'+"Qihoo-360"+'"'+", "+'"'+json_data['results']['scans']['Qihoo-360']['result']+'"]',end = ' ',file=f)
                    f.close
                except:
                    print("")

                with open('log.txt', 'a') as f:
                    print('],"'+"scan_date"+'"'":"+'"'+json_data['results']['scan_date']+'",',end = ' ',file=f)
                    print('"'+"first_seen"+'"'":"+'"2008-06-26 07:26:48"'"",",",end = ' ',file=f)
                    print('"'+"sha256"+'"'":"+" "+""+'"'+json_data['results']['sha256']+'",',end = ' ',file=f)
                    print('"'+"md5"+'"'":"+" "+""+'"'+json_data['results']['md5']+'"'"}",end = ' ',file=f)
                f.close

              
                f.close           


    def get_virustotal_result(self):
        return(self.vt_result)

    def is_malicious(self):
        # the definition of "malicious" is not fixed.
        # What we say here is that if a certain number of engines discover the file to be malicious,
        # then we deem it potentially malicious.
        # We use a ratio here, for example 0.1=10%:
        return(self.count_alerting_scanners() / self.count_total_scanners() >= self.ALERTING_LEVEL)

    def count_total_scanners(self):
        # number of AV scanners that were used to check this file
        return(self.total_scanners)

    def count_alerting_scanners(self):
        # number of AV scanners that reported the file as malicious
        return(self.positives)

    

class entityHandler:
    # manages observed entities, i.e. adds new entities if they were not observed before
    # or otherwise updates information on previously observed entities

    def __init__(self):
        self.hash_dict = {}

    def add_file(self, file, alerting_level):
        # check if other files with same hash were already processed (duplicates)
        new_file = simpleFile(file)
        existing_duplicates = self.hash_dict.get(new_file.get_hash())
        if existing_duplicates is not None:
            # Other files with an identical hash are already present, we just add the file name:
            existing_duplicates.add_file_name(new_file.get_file_name())
        else:
            # We see this hash for the first time and add it to the list:
            self.hash_dict.update({new_file.get_hash():observedEntity(new_file, alerting_level)})

    def get_entities(self):
        # returns an iterable of all observed entities so that they can be checked
        return(self.hash_dict.items())

    def count_entities(self):
        # number of entities (i.e. files with unique hash) in scope
        return(len(self.hash_dict))

    def retrieve_virustotal_results(self):
        # Starts the polling of VirusTotal results for all observed entities
        # VT rate limit is 4 requests per minute. If we have <= 4 unique hashes,
        # we can query them without waiting:
        if entity_handler.count_entities() <= 4:
           waiting_time = 0
        else:
           waiting_time = 15

        i = 0
        for hash, observed_entity in self.get_entities():
           
            observed_entity.add_virustotal_result(vt.get_file_report(hash))
          
            # The free VirusTotal API is rate-limited to 4 requests per minute.
            # If you have a premium key without rate limiting, you can remove the following line:
            time.sleep(waiting_time)
         
    
# Initialize program / load config
CONFIG_FILE= str(os.path.dirname(os.path.abspath(__file__)))+'\\config.yaml'
try:
    with open(CONFIG_FILE, 'r') as config_file:
        config = yaml.safe_load(config_file)
except FileNotFoundError:
    print(f"There was no valid {CONFIG_FILE} file in the directory of this script.")
    print("The file will be created for you, but you still need to enter your valid VirusTotal API key.")
    default_yaml = f"""
virustotal:
  api_key: enter your API key
  alerting_level: 0.1
file_path: {os.getcwd()}
recursive: True
"""
    with open(CONFIG_FILE, 'w') as config_file:
        yaml.dump(yaml.safe_load(default_yaml), config_file, default_flow_style=False)  

    sys.exit(f"\nNo valid API key in {CONFIG_FILE} file found.")
    
VT_KEY = config['virustotal']['api_key']
ALERTING_LEVEL = config['virustotal']['alerting_level']
IS_RECURSIVE = config['recursive']
FILE_PATH = config['file_path']

# if a path was provided as command line parameter, it will override the config.yaml path:
# create parser
parser = argparse.ArgumentParser()
 
# we allow to pass path and alert level as command line parameters.
# If they are present, they will override the values in config.yaml
parser.add_argument("-p", "--path", default=FILE_PATH, help="Directory of files to be checked, e.g. C:\\SuspiciousFiles\\")
parser.add_argument("-a", "--alertlv", default=ALERTING_LEVEL, type=float, help="Percentage of reporting scanners to define a file as malicious, e.g. 0.1")
parser.add_argument("-r", "--recursive", metavar="recursive", default=IS_RECURSIVE, choices=['True', 'False'], help="Include subfolders into search or not, e.g. True")

# parse the arguments
args = parser.parse_args()
FILE_PATH = args.path
ALERTING_LEVEL = args.alertlv
IS_RECURSIVE = args.recursive
waiting_time = 15


# Initializing our VirusTotal API with a key
vt = VirusTotalPublicApi(VT_KEY)

# The entity handler will take care of managing all files and their VT results
entity_handler = entityHandler()

# recursively (or optionally not) read all files from the given directory
for file in glob.iglob(FILE_PATH+'/**/*', recursive=IS_RECURSIVE):
    # only calculate the hash of a file, not of folders:
    if os.path.isfile(file):
        # we add the alerting threshold to each individual entity.
        # This allows us to work with different alerting levels per file (type).
        # For now we keep it simple and assign the same level (default: 0.1) to all of them.
        entity_handler.add_file(file, ALERTING_LEVEL)
       

# VirusTotal polling
entity_handler.retrieve_virustotal_results()

# return relevant results
findings_counter = 0
for hash, observed_entity in entity_handler.get_entities():
    if observed_entity.is_malicious():
        findings_counter+=1
        with open('log.txt', 'a') as filelog:
            print(f'====== {hash} ======',file=f)
            print('Potentially malicious hash for the following (identical) files:',file=f)
        f.close
        i = 0
        for f in observed_entity.get_file_names():
            i+=1
            with open('log.txt', 'a') as f:
              print(f'{i}: {f}',file=f)
        f.close
        with open('log.txt', 'a') as f:
            print(f'\n{observed_entity.count_alerting_scanners()} out of {observed_entity.count_total_scanners()} scanners identified this file as malicious.',file=f)
            print('--------------------------------------------------------\n\n\n',file=f)
            print(f'VT Result is: {observed_entity.get_virustotal_result()}',file=f)
        f.close
with open('log.txt', 'a') as f:
    print(f'Finished processing {entity_handler.count_entities()} files. {findings_counter} findings were reported.',file=f)
f.close