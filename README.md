# Plaintext Encryption/Decryption Demo

## What is this?
A demo client to illustrate encryption, decryption and hashing functions with AES, SHA2 and RSA.

![Alt text](/screenshots/sha2hash.png)


**_IMPORTANT DISCLAIMER!!_** This is not a secure application, or a secure or recommended way of encrypting data, it's a simple demo to illustrate the principles only. Do not use this a secure encryption example / reference code for a secure system in any way. Please refer to the numerous articles and info on encryption and security on the interwebs for that!

## Contains
- /public = CSS (stylesheet)
- /views = ejs based index.html page
- /controllers = controller code with HTTP UI rendering and encryption code
- app.js main app code

## Functionality:
- **encrypt** plaintext to cipher using password/secret (AES)
- **decrypt** cipher to plaintext using password/secret (AES)
- **hash** plaintext, using an optional password/secret (SHA-2)
- **rsa key generation** create private and public keys
- **rsa encryption** using public key
- **rsa decryption** using private key



## Acknowledgements
Based on Christoph Hartmann examples at:
http://lollyrock.com/articles/nodejs-encryption/

## Installation overview

### Clone Repo an install module dependencies

```
https://github.com/ajyounguk/crypto-demo
cd crypto-demo
npm install
```

## How to run it
node app.js

point your browser at the local/remoteIP port 3000 to load the cryptography demo html UI



### EOL Readme..
