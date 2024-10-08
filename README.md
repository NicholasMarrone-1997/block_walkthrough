---
title: "Block Walkthrough - Tryhackme"
date: 2024-08-18
---

In this detailed guide, you will learn how to analyze and decrypt encrypted SMB3 traffic using a combination of tools and techniques. Starting with the extraction and cracking of hashed passwords from a memory dump, the guide demonstrates how to calculate key exchange keys and random session keys, which are essential for decrypting SMB3 traffic captured in a PCAP file. You'll also explore the process of handling non-crackable hashes by modifying Python scripts, ultimately leading to the successful decryption and extraction of sensitive data from the network traffic.

---

From wireshark analysis, we found that the username of the first person that accessed the server was `mrealman`

I dumped the contents of the lsass.DMP with `pypkatz lsa minidump lsass.DMP`

![image](https://github.com/user-attachments/assets/6c99a9a7-2ada-4964-b48c-04b178f75fe1)


Found a hashed password, so I tried cracking it with John:
`john --format=NT --rules -w=/usr/share/wordlists/rockyou.txt password.txt`
![image](https://github.com/user-attachments/assets/38a088f7-34c4-409c-935e-7b48f5cfd0de)

So creds are mrealman : Blockbuster1

![image](https://github.com/user-attachments/assets/859fb524-4389-4529-8cab-2833a9dc312d)
I believe that something is hiding in the encrypted smb3 traffic so i decided googling how to decrypt smb3 :
https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2

**_TL;DR: Given just a PCAP of an SMB3 session, the encrypted SMB3 could be decrypted by cracking the NetNTLMv2 hash and computing the Random Session Key_**

What's needed:
```
-u, -d, -p, -n, -k, -v
-User’s password or NTLM hash  
-User’s domain  
-User’s username  
-NTProofStr  
-Key Exchange Key (Also known as the NTLMv2 Session Base Key)  
-Encrypted Session Key
```

Locating NTProofStr: Find the SMB traffic and the NTLMSSP Authentication Message within it
 - security blob -> gss-api -> simple protected negotiation -> negTokenTarg -> NTLM Secure Service Provider -> Lan Manager Response -> NTLM Response -> NTLMv2 Response 
NTProofStr: `16e816dead16d4ca7d5d6dee4a015c14`

Can calculate key exchange key with the following code:
```python
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
```

**Key Exchange Key (NTLMv2 Session Base Key)** is `d541c491e319df06e2904e622049b034`

Ran the following code to generate the Random SK which can be used to decrypt the encrypted SMB traffic
```python
import hashlib
import hmac
import argparse

# Stolen from impacket. Thank you all for your wonderful contributions to the community
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    cipher_encrypt = cipher.encrypt
    
    sessionKey = cipher_encrypt(exportedSessionKey)
    return sessionKey

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", required=True, help="Password of User")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

args = parser.parse_args()

# Upper Case User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

# Create 'NTLM' Hash of password
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

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print("USER WORK: " + user.decode('utf-16le') + "" + domain.decode('utf-16le'))
    print("PASS HASH: " + password.hex())
    print("RESP NT: " + respNTKey.hex())
    print("NT PROOF: " + NTproofStr.hex())
    print("KeyExKey: " + KeyExchKey.hex())
    print("Random SK: " + RsessKey.hex())
```

`python3 randomsessionkey.py -u mrealman -d BLOCK -p Blockbuster1 -n 16e816dead16d4ca7d5d6dee4a015c14 -k d541c491e319df06e2904e622049b034 -v`
![image](https://github.com/user-attachments/assets/d8a22c13-61d5-411b-bf7a-84696af84516)
Random SK: `58d5fb48b862bff237da736c231edcd4`

I wasn't able to decrypt the traffic for the first user using the session ID: NTProofStr. So, I did some research and found this article. Instead, I tried decrypting NTLMSSP, which successfully decrypted the SMB3 encrypted traffic.
![image](https://github.com/user-attachments/assets/a822706f-6af5-4a11-bfbe-6aa12930a1c9)
![image](https://github.com/user-attachments/assets/631ac89e-3be6-4c6f-ba41-78a7259ca418)


Inside the decrypted traffic, we find two csv files:
![image](https://github.com/user-attachments/assets/19cf2f26-25b0-4534-8b10-07ef7cfc9abc)


I used File -> Export Objects -> SMB to extract the objects.
![image](https://github.com/user-attachments/assets/1f9c8ce8-8861-4485-8967-abdef125ca59)


Second User
For the second user, the hash 3f29138a04aadc19214e9c04028bf381 was not crackable. Therefore, I modified the script to provide the hash in place of the password:
`python3 randomsessionkey.py -u eshellstrop -d WORKGROUP -H 3f29138a04aadc19214e9c04028bf381 -n 0ca6227a4f00b9654a48908c4801a0ac -k c24f5102a22d286336aac2dfa4dc2e04 -v`

The output was:
`Random SK: facfbdf010d00aa2574c7c41201099e8`

We then used the random SK value, placed it in the session key and session ID from Wireshark. Remember, this value is in hex and needs to be converted from big endian to little endian.
![image](https://github.com/user-attachments/assets/cda85d7b-a437-410c-9c63-da0c6a799d1f)


This decrypted the CSV file, which I exported and opened and found the final flag
