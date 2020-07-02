"use strict";

const EventEmitter = require('events');
const crypto = require("crypto");
const request = require("./request");
const base64url = require("./base64url");
const sha256 = require("./sha256");

class ACMERequester {

    constructor(accountKey) {
        this.accountKey = accountKey;
        // get a starting token
        this.nonce = null;
        this.directory = null;
        // start
        this.init();
    }

    init(){
      // event listener
      this.event = new EventEmitter();
      // get endpoints
      this.getDirectory();

    }

    request(url, payload, options) {
        return request("/directory").then((result) => {
            let nonce = result.headers["replay-nonce"];
            let payload64 = base64url(JSON.stringify(payload));
            let protectedHeader = Object.assign({}, this.accountKey.header, {nonce: nonce});
            let protectedHeader64 = base64url(JSON.stringify(protectedHeader));
            let signature = crypto.createSign("RSA-SHA256").update(protectedHeader64 + "." + payload64).sign(this.accountKey.pem);
            let signature64 = base64url(signature);
            let data = JSON.stringify({
                header: this.accountKey.header,
                protected: protectedHeader64,
                payload: payload64,
                signature: signature64,
            });
            return request(url, Object.assign({method: "POST", body: data}, options));
        });
    },

    getNonce() {
      var self = this;
      //response, err := http.Get("https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce")
    	return request(this.directory.newNonce, {}, function( err, result, body){
        //console.log("Nonce result", result.headers);
        self.nonce = result.headers["replay-nonce"];
        self.event.emit('nonce', self.nonce);
      });
    }

    getDirectory(){
      var self = this;
      //response, err := http.Get("https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce")
      return request( this.options.url +"/directory", {}, function( err, result, body){
        //console.log("Directory response:", body);
        self.directory = JSON.parse(body);
        self.event.emit('directory', self.directory);
        self.getNonce();
      });
    }

}

module.exports = ACMERequester;
