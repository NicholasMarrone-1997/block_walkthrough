---
title: "Block Walkthrough - Tryhackme"
date: 2024-08-18
---
Wireshark Analysis and Decrypting SMB3 Traffic
Step 1: Extracting Credentials
From the Wireshark analysis, we identified that the first person to access the server used the username mrealman.

I dumped the contents of the lsass.DMP file using the following command:

bash
Copy code
pypkatz lsa minidump lsass.DMP

I found a hashed password and attempted to crack it with John the Ripper:

bash
Copy code
john --format=NT --rules -w=/usr/share/wordlists/rockyou.txt password.txt

Credentials found:
mrealman : Blockbuster1

Step 2: Decrypting SMB3 Traffic
I suspected something was hidden in the encrypted SMB3 traffic, so I researched how to decrypt SMB3. I found a useful guide: Decrypting SMB3 Traffic.

TL;DR:
Given a PCAP of an SMB3 session, the encrypted SMB3 traffic can be decrypted by cracking the NetNTLMv2 hash and computing the Random Session Key.

Requirements:

diff
Copy code
- User’s password or NTLM hash  
- User’s domain  
- User’s username  
- NTProofStr  
- Key Exchange Key (NTLMv2 Session Base Key)  
- Encrypted Session Key
Example variables:

css
Copy code
-u, -d, -p, -n, -k, -v
NTProofStr:
16e816dead16d4ca7d5d6dee4a015c14

Step 3: Calculating the Key Exchange Key
I used the following Python code to calculate the Key Exchange Key:

python
Copy code
import hmac
import hashlib

# NT hash and NTProofStr
nt_hash = bytes.fromhex('1f9175a516211660c7a8143b0f36ab44')
nt_proof_str = bytes.fromhex('16e816dead16d4ca7d5d6dee4a015c14')

# Calculate the Key Exchange Key
key_exchange_key = hmac.new(nt_hash, nt_proof_str, hashlib.md5).digest()

# Convert to hexadecimal format for display
key_exchange_key_hex = key_exchange_key.hex()

print(f"Key Exchange Key (NTLMv2 Session Base Key): {key_exchange_key_hex}")
Key Exchange Key (NTLMv2 Session Base Key):
d541c491e319df06e2904e622049b034

Step 4: Generating the Random Session Key
Next, I generated the Random Session Key, which is crucial for decrypting the encrypted SMB traffic:

python
Copy code
import hashlib
import hmac
import argparse

# Importing necessary crypto libraries
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    print("Warning: You don't have any crypto installed. You need pycryptodomex")
    print("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    sessionKey = cipher.encrypt(exportedSessionKey)
    return sessionKey

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP.")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", required=True, help="Password of User")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr (Hex Stream)")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key (Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

args = parser.parse_args()

# Uppercase User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

# Create 'NTLM' Hash of the password
passw = args.password.encode('utf-16le')
hash1 = hashlib.new('md4', passw)
password = hash1.digest()

# Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting the Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print(f"USER: {user.decode('utf-16le')} DOMAIN: {domain.decode('utf-16le')}")
    print(f"PASS HASH: {password.hex()}")
    print(f"RESP NT: {respNTKey.hex()}")
    print(f"NT PROOF: {NTproofStr.hex()}")
    print(f"Key Exchange Key: {KeyExchKey.hex()}")
    print(f"Random Session Key: {RsessKey.hex()}")
Command to generate the Random Session Key:

bash
Copy code
python3 randomsessionkey.py -u mrealman -d BLOCK -p Blockbuster1 -n 16e816dead16d4ca7d5d6dee4a015c14 -k d541c491e319df06e2904e622049b034 -v

Random SK:
58d5fb48b862bff237da736c231edcd4

Step 5: Handling Non-Crackable Hashes
I encountered an issue with another user (eshellstrop) whose hash was not crackable. I modified the script to accept a hash instead of a password:

bash
Copy code
python3 randomsessionkey.py -u eshellstrop -d WORKGROUP -H 3f29138a04aadc19214e9c04028bf381 -n 0ca6227a4f00b9654a48908c4801a0ac -k c24f5102a22d286336aac2dfa4dc2e04 -v

Random SK:
facfbdf010d00aa2574c7c41201099e8

This allowed me to decrypt the remaining SMB3 traffic.

Conclusion
Using the decrypted Random Session Keys, I was able to successfully decrypt the SMB3 traffic, export the objects, and analyze the contents.
