# OpenPGP in LUA
This is OpenPGP library used for LUA which converted from https://github.com/calccrypto/OpenPGP  
## Building
Please check how to build [OpenPGP in C++](https://github.com/calccrypto/OpenPGP#building)
## Use
Function | Description
---------|------------------------------------------
   getSecretKey  | reads secret key from file
   getPublicKey  | reads public key from file
   getEncryptMsg   | Encrypt a text 
   getDecryptMsg | Decrypt a text.
   getSignMsg | Sign a text.
   getVerifyMsg   | Verify a text.
   getFingerprint   | get public key's fingerprint.
