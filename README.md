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

I wasn't able to decrypt the traffic for this first user using the session ID : NTProofStr, so I did some research.
Found this article: https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7. 
So I instead tried decrypting NTLMSSP and it decrypted the SMB3 encrypted traffic:
![image](https://github.com/user-attachments/assets/10f4dd0f-350c-4808-a2f5-8afaf1a66fb7)
![image](https://github.com/user-attachments/assets/f920df8b-2b19-43e9-8b93-0bc006c4a35c)
and inside the once encrypted traffic we find...
![image](https://github.com/user-attachments/assets/ccfe9d9a-35bd-47bc-bd7b-823210f93fc2)


File -> Export Objects -> SMB
![image](https://github.com/user-attachments/assets/f5e535af-2219-4670-931e-b0d945093fd0)

Second user:
![image](https://github.com/user-attachments/assets/138508a2-e37e-4cdd-83e2-ab499c170bc2)

eshellstrop
NT: 3f29138a04aadc19214e9c04028bf381

we do same process before like we do in the first user to decrypt the connection but here the user eshellstrop hash is not crackable so what we gone do to modify our script to provide hash in place of password so i modify it
`python3 randomsessionkey.py -u eshellstrop -d WORKGROUP -H 3f29138a04aadc19214e9c04028bf381 -n 0ca6227a4f00b9654a48908c4801a0ac -k c24f5102a22d286336aac2dfa4dc2e04 -v`

![image](https://github.com/user-attachments/assets/d280d595-af84-449d-b578-c88127d0cb75)
Random SK: facfbdf010d00aa2574c7c41201099e8

then like before we do the random sk value put in session key and session id from the wireshark don’t forget it placed in hex value and little endian means we should reverse it

![image](https://github.com/user-attachments/assets/f40f2c14-4b8a-4ef3-bd7e-60766b7e0f2f)
Big endian -> little endian

This decrypted the other csv file so I exported it and opened it
