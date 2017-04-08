import os, sys
import json
from sets import Set
from time import sleep
from CVEClass import CVEClass
from RepeatedTimer import RepeatedTimer

print "starting..."
cveClass = CVEClass()
rt = RepeatedTimer(10, cveClass.cveUpdate, "World")

try:
    while True:
        sleep(60) #Update every minute
except Exception as e:
    e.msg()
finally:
    rt.stop()
