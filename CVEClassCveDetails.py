import os
import json
import requests
from CustQueue import CustQueue
from ares import CVESearch
from dateutil import parser
from MastodonClass import MastodonClass

'''
This CVE Class pulls details from:
    http://www.cvedetails.com
'''
class CVEClassCveDetails:

    def __init__(self):
        self.cve = CVESearch()
        self.store_name = 'cvestoredetails.db'
        self.cached_cve_ids = []
        self.message_queue = CustQueue()
        self.mastodonClass = MastodonClass()
        self.mastodonClass.initalize()
        self.readCVEListFromFile()
        self.url = "http://www.cvedetails.com/json-feed.php?numrows=30&vendor_id=0&product_id=0&version_id=0&hasexp=0&opec=0&opov=0&opcsrf=0&opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opginf=0&opdos=0&orderby=3&cvssscoremin=6"

    def cveUpdate(self):

        r = requests.get(self.url)
        cves = r.json()
        str_list = []

        for result in cves:
            cve_string = ""

            if result['cve_id'].strip() in self.cached_cve_ids:
                pass
            else:

                if len(self.cached_cve_ids) == 30:
                    self.cached_cve_ids.pop()

                self.cached_cve_ids.append(str(result['cve_id']))
                self.cached_cve_ids = sorted(self.cached_cve_ids, reverse=True)
                
                cve_string += "New CVE Notification"
                cve_string += "\n\n"
                cve_string += "CVE ID: " + result['cve_id'] + "\n\n"
                cve_string += "CVSS Score: "+ result['cvss_score']+"\n\n"
                cve_string += "Publish Date: "
                cve_string += result['publish_date']+ "\n\n"               
                cve_string += "Summary: "
                cve_string += result['summary'][:197] +"...\n\n"
                cve_string += "URL: " + result['url'] + "\n"

                str_list.append(cve_string +"\n")

        for revstr in list(reversed(str_list)):
            self.message_queue.enqueue(revstr)

        self.writeCVEListToFile()

    def dequeueMessage(self):
        if self.message_queue.size() > 0:
            #print self.message_queue.dequeue()
            self.shareToMastodon(self.message_queue.dequeue())

    def shareToMastodon(self, cve_str):
        self.mastodonClass.toot(cve_str)

    def readCVEListFromFile(self):
        print "Reading CVEList from file"
        if os.path.isfile(self.store_name):
            with open(self.store_name, 'r') as cveStoreFile:
                data= cveStoreFile.read().replace('\n', '')

                for result in json.loads(data):
                    self.cached_cve_ids.append(str(result))

    def writeCVEListToFile(self):
        print "Writing CVEList to file"
        file = open(self.store_name, 'w')
        file.write(json.dumps(self.cached_cve_ids))
        file.close()