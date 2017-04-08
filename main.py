import os, sys
import json
from sets import Set
from time import sleep
from CVEClass import CVEClass
from RepeatedTimer import RepeatedTimer

print "starting..."
cveClass = CVEClass()
rt = RepeatedTimer(300, cveClass.cveUpdate, "World") # Update every 5 minutes

try:
    while True:
        sleep(60) #Large sleep value
except Exception as e:
    e.msg()
finally:
    rt.stop()
