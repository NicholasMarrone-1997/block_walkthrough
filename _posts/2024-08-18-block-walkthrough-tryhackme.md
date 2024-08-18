---
title: "Block Walkthrough - Tryhackme"
date: 2024-08-18
---

From wireshark analysis, we found that the username of the first person that accessed the server was `mrealman`

I dumped the contents of the lsass.DMP with `pypkatz lsa minidump lsass.DMP`

![[Pasted image 20240817180628.png]]

Found a hashed password, so I tried cracking it with John:
`john --format=NT --rules -w=/usr/share/wordlists/rockyou.txt password.txt`
![[Pasted image 20240817180711.png]]
So creds are mrealman : Blockbuster1

![[Pasted image 20240817181253.png]]
I believe that something is hiding in the encrypted smb3 traffic so i decided googling how to decrypt smb3 :
https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2

**_TL;DR: Given just a PCAP of an SMB3 session, the encrypted SMB3 could be decrypted by cracking the NetNTLMv2 hash and computing the Random Session Key_**

What's needed:
```
-User’s password or NTLM hash  
-User’s domain  
-User’s username  
-NTProofStr  
-Key Exchange Key (Also known as the NTLMv2 Session Base Key)  
-Encrypted Session Key
```

-u, -d, -p, -n, -k, -v

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
|   |
|---|
|import hashlib|
||import hmac|
||import argparse|
|||
||#stolen from impacket. Thank you all for your wonderful contributions to the community|
||try:|
||from Cryptodome.Cipher import ARC4|
||from Cryptodome.Cipher import DES|
||from Cryptodome.Hash import MD4|
||except Exception:|
||LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")|
||LOG.critical("See https://pypi.org/project/pycryptodomex/")|
|||
||def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):|
||cipher = ARC4.new(keyExchangeKey)|
||cipher_encrypt = cipher.encrypt|
|||
||sessionKey = cipher_encrypt(exportedSessionKey)|
||return sessionKey|
||###|
|||
||parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")|
||parser.add_argument("-u","--user",required=True,help="User name")|
||parser.add_argument("-d","--domain",required=True, help="Domain name")|
||parser.add_argument("-p","--password",required=True,help="Password of User")|
||parser.add_argument("-n","--ntproofstr",required=True,help="NTProofStr. This can be found in PCAP (provide Hex Stream)")|
||parser.add_argument("-k","--key",required=True,help="Encrypted Session Key. This can be found in PCAP (provide Hex Stream)")|
||parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")|
|||
||args = parser.parse_args()|
|||
||#Upper Case User and Domain|
||user = str(args.user).upper().encode('utf-16le')|
||domain = str(args.domain).upper().encode('utf-16le')|
|||
||#Create 'NTLM' Hash of password|
||passw = args.password.encode('utf-16le')|
||hash1 = hashlib.new('md4', passw)|
||password = hash1.digest()|
|||
||#Calculate the ResponseNTKey|
||h = hmac.new(password, digestmod=hashlib.md5)|
||h.update(user+domain)|
||respNTKey = h.digest()|
|||
||#Use NTProofSTR and ResponseNTKey to calculate Key Excahnge Key|
||NTproofStr = args.ntproofstr.decode('hex')|
||h = hmac.new(respNTKey, digestmod=hashlib.md5)|
||h.update(NTproofStr)|
||KeyExchKey = h.digest()|
|||
||#Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4|
||RsessKey = generateEncryptedSessionKey(KeyExchKey,args.key.decode('hex'))|
|||
||if args.verbose:|
||print "USER WORK: " + user + "" + domain|
||print "PASS HASH: " + password.encode('hex')|
||print "RESP NT: " + respNTKey.encode('hex')|
||print "NT PROOF: " + NTproofStr.encode('hex')|
||print "KeyExKey: " + KeyExchKey.encode('hex')|
||print "Random SK: " + RsessKey.encode('hex')|
```

`python3 randomsessionkey.py -u mrealman -d BLOCK -p Blockbuster1 -n 16e816dead16d4ca7d5d6dee4a015c14 -k d541c491e319df06e2904e622049b034 -v`
![[Pasted image 20240818115502.png]]
Random SK: `58d5fb48b862bff237da736c231edcd4`
 - Kind of hit a dead end with this

Found this article: https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7
![[Pasted image 20240818121600.png]]
I instead tried decrypting NTLMSSP and it decrypted the SMB3 encrypted traffic
![[Pasted image 20240818121912.png]]
![[Pasted image 20240818130100.png]]
File -> Export Objects -> SMB
![[Pasted image 20240818130932.png]]

Second user:
![[Pasted image 20240818131314.png]]
eshellstrop
NT: 3f29138a04aadc19214e9c04028bf381

we do same process before like we do in the first user to decrypt the connection but here the user eshellstrop hash is not crackable so what we gone do to modify our script to provide hash in place of password so i modify it
`python3 randomsessionkey.py -u eshellstrop -d WORKGROUP -H 3f29138a04aadc19214e9c04028bf381 -n 0ca6227a4f00b9654a48908c4801a0ac -k c24f5102a22d286336aac2dfa4dc2e04 -v`
![[Pasted image 20240818132652.png]]
Random SK: facfbdf010d00aa2574c7c41201099e8

then like before we do the random sk value put in session key and session id from the wireshark don’t forget it placed in hex value and little endian means we should reverse it

![](https://miro.medium.com/v2/resize:fit:770/1*58jobTx53th9lxGxc-_tXw.png)Big endian -> little endian

This decrypted the other csv file so I exported it and opened it
