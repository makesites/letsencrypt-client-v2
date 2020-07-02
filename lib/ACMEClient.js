"use strict";

const childProcess = require("child_process");
const PrivateKey = require("./PrivateKey");
const ACMERequester = require("./ACMERequester");
const base64url = require("./base64url");
const request = require("./request");

class ACMEClient {

    constructor(accountKey, options) {
        this.accountKey = new PrivateKey(accountKey);
        this.requester = new ACMERequester(this.accountKey);
        this.options = options || {};
        this.state = {};
        // init
        this.init();
    }

    init(){
      // events
      // - event: broadcast directory to main class
      this.requester.event.on('directory', this.onDirectory.bind(this) );
      this.requester.event.on('nonce', this.onNonce.bind(this) );
      /*
      this.nonce = this.requester.getNonce().then(function(response){
        nonce = response; //  error control?
      });
      */
    }

    register( email ) {
        // prerequisite(s)
        if( !email ) return console.log("Register Error: no email provided");
      	// variables
        var self = this;
      	var accountUrl = this.directory.newAccount;

      	var payload = {
      		termsOfServiceAgreed: true,
      		onlyReturnExisting: false, // flag behind option setting?
      		contact: [ 'mailto:'+ email ]
      	};

        return this.requester.request(accountUrl, payload).then(function( res ) {
      	    //console.log('Register response:', res );
            self.account = JSON.parse(res.body);
            self.kid = res.headers['location'];
            //console.log('Next nonce:', nonce);
            self.state.login = true;
            // continue
            return res;
      });

    }

    requestAuthorization(domain) {
        return this.requester.request("/acme/new-authz", {
            resource: "new-authz",
            identifier: {"type": "dns", "value": domain},
        }).then((result) => {
            if (result.statusCode != 201) {
                throw new Error("Error requesting authorization: " + result.statusCode + " " + result.body);
            }
            let json = JSON.parse(result.body);
            let challenge = json.challenges.find((challenge) => challenge.type == "http-01");
            challenge.path = "/.well-known/acme-challenge/" + challenge.token;
            challenge.keyAuthorization = challenge.token + "." + this.accountKey.thumbprint;
            return challenge;
        });
    }

    triggerChallenge(challenge) {
        return this.requester.request(challenge.uri, {
            resource: "challenge",
            keyAuthorization: challenge.keyAuthorization,
        }).then((result) => {
            if (result.statusCode != 202) {
                throw new Error("Error triggering challenge: " + result.statusCode + " " + result.body);
            }
        });
    }

    checkChallenge(challenge) {
        return request(challenge.uri).then((result) => {
            if (result.statusCode != 202) {
                throw new Error("Error checking challenge: " + result.statusCode + " " + result.body);
            }
            let json = JSON.parse(result.body);
            return json.status;
        });
    }

    requestCertificate(csr) {
        return this.requester.request("/acme/new-cert", {
            resource: "new-cert",
            csr: base64url(convertPEMtoDER(csr)),
        }, {encoding: null}).then((result) => {
            if (result.statusCode != 201) {
                throw new Error("Error requesting certificate: " + result.statusCode + " " + result.body);
            }
            let pem = convertDERtoPEM(result.body, "CERTIFICATE");
            return pem;
        });
    }

    // Events
    onDirectory( directory ){
        this.directory = directory; // error control?
    }

    onNonce(){
        // login if email provided
        if( this.options.email ) this.register( this.options.email );
    }

}

function convertPEMtoDER(pem) {
    return new Buffer(pem.toString().replace(/(^\s+|\s*$)/, "").split("\n").slice(1, -1).join(""), "base64");
}

function convertDERtoPEM(der, title) {
    title = title.toUpperCase();
    let body = der.toString("base64");
    let lines = [];
    lines.push("-----BEGIN " + title + "-----");
    for (let i = 0; i < body.length; i += 64) {
        lines.push(body.substr(i, 64));
    }
    lines.push("-----END " + title + "-----");
    lines.push();
    return lines.join("\n");
}

module.exports = ACMEClient;
