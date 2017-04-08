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
        sleep(10) # your long-running job goes here...
except Exception as e:
    e.msg()
finally:
    rt.stop() # better in a try/finally block to make sure the program ends!
