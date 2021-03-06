# LetsEncrypt client v2

Implementation of the [ACME protocol](https://letsencrypt.github.io/acme-spec/) to request certificates from [Let's Encrypt](https://letsencrypt.org/). Supporting LetsEncrypt's v2 API with minimal dependencies

## Installation

```
npm install letsencrypt-client-v2
```

## Usage

### constructor(acccountKey, options)

Create a client by providing the PEM encoded account private key.

```
'use strict'

const fs = require("fs");
const LEClient = require("letsencrypt-client");

let accountKey = fs.readFileSync("account.key");

let client = new LEClient(accountKey);
```

To create a new private key, use the following OpenSSL command:

```
openssl genrsa 4096 > account.key
```

#### Options 

* **email**: account email to login
* **staging**: use the staging API (instead)
  

### register()

To register or login with Let's Encrypt, use the ```register()``` method.

```
client.register(email).then(() => {
    console.log("Registered successfully");
}, (error) => {
    console.log("An error occured", error);
});
```

This method returns a standard ES6 Promise.

Note: If an email is passed in the constructor options the client will try to call this method automatically.

### start(domains)

Initiate an order for the domain variations of an SSL certificate.
```
let domains = ['www.domain.com', 'domain.com'];
client.start(domains).then(function(){
  // loop through all domains
});
```

### requestAuthorization(domain)

To request a domain verification challenge, use the ```requestAuthorization(domain)``` method, by providing the domain that needs to be verified.

```
let domain = "example.com";
client.requestAuthorization(domain).then((challenge) => {
    console.log("Domain verification challenge requested successfully");
    console.log(challenge);
}, (error) => {
    console.log("An error occured", error);
});
```

This method returns a standard ES6 Promise.

The resulting ```challenge``` object will contain a ```path``` key with the path that the Let's Encrypt server will request, and a ```keyAuthorization``` key with the value that should be returned to the Let's Encrypt request.

### triggerChallenge(challenge)

Once the HTTP server has been configured to respond with the correct value, use the ```triggerChallenge(challenge)``` method to trigger the challenge. Pass the challenge object from the ```requestAuthorization(domain)``` method.

```
client.triggerChallenge(challenge).then((res) => {
    console.log("Challenge triggered successfully");
    // poll url is in the response
    challenge.poll = res.url;
    // no need to poll if already valid, continue to the next domain (check if any left in the order)
    if(res.status == "valid") return;
    // otherwhise check the challenge with: client.checkChallenge(challenge)...
}, (error) => {
    console.log("An error occured", error);
});
```

This method returns a standard ES6 Promise.

### checkChallenge(challenge)

You can check the status of a challenge with the ```checkChallenge(challenge)``` method. Pass the challenge object from the ```requestAuthorization(domain)``` method.

```
client.checkChallenge(challenge).then((status) => {
    console.log("Challenge checked successfully");
    console.log(status);
}, (error) => {
    console.log("An error occured", error);
});
```

This method returns a standard ES6 Promise.

The status value can be ```pending```, ```valid``` (domain ownership confirmed) or ```invalid``` (domain ownership failed).

### requestCertificate(csr)

Once all the domains of the certificate signing request (CSR) have been validated, use the ```requestCertificate(csr)``` method to request the certificate. The PEM encoded CSR needs to be provided.

```
let csr = fs.readFileSync("domain.csr");
client.requestCertificate(csr).then((certificate) => {
    console.log("Certificate requested successfully");
    console.log(certificate);
}, (error) => {
    console.log("An error occured", error);
});
```

This method returns a standard ES6 Promise.

The resulting ```certificate``` will contain the PEM encoded certificate string.

To create a new certificate signing request, use the following OpenSSL command (from [diafygi/acme-tiny](https://github.com/diafygi/acme-tiny)):

```
#for a single domain
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr

#for multiple domains (use this one if you want both www.yoursite.com and yoursite.com)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
```

## Credits 

Based on the module [letsencrypt-client](https://github.com/quentinadam/node-letsencrypt-client) by [Quentin Adam](quentinadam@gmail.com)



