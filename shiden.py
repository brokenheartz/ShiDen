#!/usr/bin/python3

from package.color import *
from package.detect import detect
import os, time, sys

def loading():
    try :
        for point in range(10):
            print(".", end = "")
            time.sleep(0.05)
            sys.stdout.flush()
        print()
    except (KeyboardInterrupt, SystemExit):
        pass

print(CYAN + BOLD + """
      _     _ _____             
     | |   (_)  __ \            
  ___| |__  _| |  | | ___ _ __  
 / __| '_ \| | |  | |/ _ \ '_ \ 
 \__ \ | | | | |__| |  __/ | | |
 |___/_| |_|_|_____/ \___|_| |_|
 """ + DIM + RED +  "\t  --- Ha" + NORMAL + WHITE + "shiDen" + RED + DIM + "tifier ---".strip())

try :
    hash = input("\n" + YELLOW + "(file/hash) :: ")
except (KeyboardInterrupt,SystemExit):
    print("\n[!] Exiting Program ", end = "")
    loading()
    sys.exit(0)

if os.path.isfile(hash):
    for h in open(hash).readlines():
        detect(h.strip())
else :
    detect(hash.strip())
