from base64 import b64decode, b32decode
from package.color import *

class detectHashEnc :
    found = 0

    def __init__(self, hash):
        self.hash = hash
        print(BOLD + GREEN + "-" * 60)
        print(BLUE + "Hash" + MAGENTA +  " : " + WHITE + self.hash)
        print()
        self.detect()

    def __del__(self):
        COLOR = BOLD + RED if detectHashEnc.found == 0 else BOLD + GREEN
        print()
        print(BLUE + "[+] " + COLOR + str(detectHashEnc.found) + NORMAL + WHITE + " possible hash(es) found.")
        print(BOLD + GREEN + "-" * 60)

    def detect(self):
        hash = self.hash
        true = 0 # count correct hash(es)
    
        # Analyzing Hash
        if ((not hash.isalpha() and not hash.isdigit()) and hash.isalnum()) and len(hash) == 32:
            possibleHashes = [
                    "MD4 (Message-Digest algorithm 4)","MD5 (Message-Digest algorithm 5)",
                    "MD5($pass.$salt)","MD5($salt.$pass)","MD2 (Message-Digest algorithm 2)", "md5(md5($pass).$salt)",
                    "RipeMD-128","RipeMD-128HMAC"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 128:
            possibleHashes = ["SHA-512","SHA-512HMAC","Whirlpool","WhirlpoolHMAC"]
            for x in possibleHashes :
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("sha384") and len(hash) == 110:
            print(GREEN + "[+]" + YELLOW + " SHA-384(Django)")
            true += 1
        elif (((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 64):
            possibleHashes = ["SHA-256","SHA-256HMAC","Haval-256", "Haval-256HMAC", "GOST R 34.11.94",
                    "RipeMD-256", "RipeMD-256HMAC", "SNEFRU-256", "SNEFRU-256HMAC", "SHA-256md5pass", 
                    "SHA-256sha1pass"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 96:
            possibleHashes = ["SHA-384", "SHA-384HMAC"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 80:
            possibleHashes = ["RipeMD-320", "RipeMD-320HMAC"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("$P$B") and len(hash) == 34:
            print(GREEN + "[+]" + YELLOW + " MD5 (WordPress)")
            true += 1
        elif hash.startswith("$1$") and len(hash) == 34:
            print(GREEN + "[+]" + YELLOW + " MD5 (Unix)")
            true += 1
        elif hash.startswith("$H$") and len(hash) == 34:
            print(GREEN + "[+]" + YELLOW + " MD5 (phpBB3)")
            true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 40:
            possibleHashes = ["SHA-1", "RipeMD-160", "RipeMD-160HMAC", "Tiger-160", "Haval-160", "SHA-1(HMAC)",
                    "Tiger-160(HMAC)", "Haval-160(HMAC)", "SHA-1(MaNGOS)", "SHA-1(MaNGOS2)", "MySQL5 - SHA-1(SHA-1($pass))" , 
                    "sha1($pass.$salt)", "sha1($salt.$pass)", "sha1($salt.md5($pass))", "sha1($salt.md5($pass).$salt)", 
                    "sha1($salt.sha1($pass))", "sha1($salt.sha1($salt.sha1($pass)))", "sha1($username.$pass)", 
                    "sha1($username.$pass)", "sha1($username.$pass.$salt)", "sha1(md5($pass))", "sha1(md5($pass).$salt)",
                    "sha1(md5(sha1($pass)))", "sha1(sha1($pass))", "sha1(sha1($pass).$salt)", "sha1(sha1($pass).substr($pass,0,3))",
                    "sha1(sha1($salt.$pass))", "sha1(sha1(sha1($pass)))", "sha1(strtolower($username).$pass)"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("$6$") and len(hash) == 98:
            print(GREEN + "[+]" + YELLOW + " SHA-256s")
            true += 1
        elif hash.startswith("sha256") and len(hash) == 78:
            print(GREEN + "[+]" + YELLOW + " SHA-256(Django)")
            true += 1
        elif len(hash) == 65 and hash.find(":") != -1 and not hash.islower():
            print(GREEN + "[+]" + YELLOW + " SAM - (LM_hash:NT_hash)")
            print(GREEN + "[+]" + YELLOW + " md5($pass.$salt) - Joomla")
            true += 2
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 56:
            possibleHashes = ["SHA-224","SHA-224(HMAC)","Haval-224","Haval-224(HMAC)"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("sha1") and len(hash) == 52:
            print(GREEN + "[+]" + YELLOW + " SHA-1(Django)")
            true += 1
        elif len(hash) == 41 and hash.find(":") != -1:
            print(GREEN + "[+]" + YELLOW + " md5($pass.$salt) - Joomla")
            true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 48:
            possibleHashes = ["Tiger-192", "Tiger-192(HMAC)", "Haval-192", "Haval-192(HMAC)"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("*") and len(hash) == 41:
            print(GREEN + "[+]" + YELLOW + " MySQL 160bit - SHA-1(SHA-1($pass))")
            true += 1
        elif hash.startswith("$apr") and len(hash) == 37:
            print(GREEN + "[+]" + YELLOW + " MD5(APR)")
            true += 1
        elif ((not hash.isalpha() and not hash.isdigit())) and hash.isalnum() and len(hash) == 16:
            possibleHashes = ["MySQL", "MD5(Middle)", "MD5(Half)"]
            for x in possibleHashes:
                print(GREEN + "[+]" + YELLOW + " " + x)
                true += 1
        elif hash.startswith("$2y$") and len(hash) == 60:
            print(GREEN + "[+]" + YELLOW + " Bcrypt Hash Algorithm")
            true += 1

        # Analyzing Encoding
        try : # base64 
            if b64decode(hash).decode("ascii") : 
                print(GREEN + "[+]" + YELLOW + " Base64 Encoding")
                true += 1
        except Exception : pass

        try : # base32
            if b32decode(hash).decode("ascii") : 
                print(GREEN + "[+]" + YELLOW + " Base32 Encoding")
                true += 1
        except Exception : pass

        detectHashEnc.found = true

def detect(x):
    if x.isspace() or x == "":
        print(RED + "[-] Input correct hash string!")
    else :
        hash = detectHashEnc(x)
