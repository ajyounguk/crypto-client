# Plaintext Encryption/Decryption Demo

## What is this?
This application provides a Node.js webserver, and a html interface to demonstrate the principles of encryption, decryption and hashing.

**_IMPORTANT DISCLAIMER_** This is not a secure application, or a secure way of encrypting data, it's a simple demo to illustrate the principles only. Do not use this a secure encryption example / reference code for a secure system in any way. Please refer to the numerous articles and info on encryption and security on the interwebs for that. 

## Contains
- /public = CSS (stylesheet)
- /views = ejs based index.html page
- /controllers = controller code with HTTP UI rendering and encryption code
- app.js main app code

## Functionality:
- **encrypt** plaintext to cipher using password/secret
- **decrypt** cipher to plaintext using password/secret
- **hash** plaintext, using an optional password/secret

### todo :
- hashing example

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

point your browser at the local/remoteIP port 3000 to load the HTML UI



### EOL Readme..
