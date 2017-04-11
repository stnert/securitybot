import os, sys
import json
from sets import Set
from time import sleep
from CVEClassCveDetails import CVEClassCveDetails
from RepeatedTimer import RepeatedTimer

print "Starting the security bot..."

cveClass = CVEClassCveDetails()
cveClassRt = RepeatedTimer(300, cveClass.cveUpdate) # Update every 5 minutes
cvePostRt = RepeatedTimer(1680, cveClass.dequeueMessage) # Post every 28 minutes

try:
    while True:
        sleep(60)
except Exception as e:
    e.msg()
finally:
    cveClassRt.stop()
    cvePostRt.stop()
