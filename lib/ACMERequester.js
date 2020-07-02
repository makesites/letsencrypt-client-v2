"use strict";

const EventEmitter = require('events');
const crypto = require("crypto");
const request = require("request");
const apiRequest = require("./request");
const base64url = require("./base64url");
const sha256 = require("./sha256");

class ACMERequester {

    constructor(accountKey, options) {
        this.accountKey = accountKey;
        this.options = options;
        this.options.url = ( this.options.staging )
          ? 'https://acme-staging-v02.api.letsencrypt.org'
          : 'https://acme-v02.api.letsencrypt.org';

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
        // fallbacks
        options = options || {};
        var self = this;
        // wait until we have a token
        return new Promise((resolve, reject) => {
            if( self.nonce == null ){
                // first request came in too soon, wait for nonce
                console.log("Request timeout...");
                return setTimeout(function(){ self.request(url, payload, options); }, 1000);
            }
            let payload64 = (payload != "") ? base64url(JSON.stringify(payload)) : ""; // FIX: emprty string doesn't need to be encoded
            let account = ( options.kid ) ? { kid : options.kid } : self.accountKey.header;
            let protectedHeader = Object.assign({}, account, {nonce: self.nonce, url: url, alg: 'RS256' });
            let protectedHeader64 = base64url(JSON.stringify(protectedHeader));
            let signature = crypto.createSign("RSA-SHA256").update(protectedHeader64 + "." + payload64).sign(self.accountKey.pem);
            let signature64 = base64url(signature);
            let data = JSON.stringify({
                protected: protectedHeader64,
                payload: payload64,
                signature: signature64
            });
            apiRequest(url, {mode: 'cors', method: "POST", body: data}).then((res) => {
                //console.log(res);
                // save new token
                self.nonce = res.headers["replay-nonce"];
                //return
                resolve(res);
            });

        });
    }

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
