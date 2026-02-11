"use strict";

const crypto = require("crypto");
const request = require("request");
const apiRequest = require("./request");
const base64url = require("./base64url");
const sha256 = require("./sha256");

class ACMEOrder {

    constructor(options) {
        options = options || {};
        // variables
        this.requester = options.requester;
        delete options.requester;

        this.options = options;
        this.data = null;
    }

    create(domains){
      var self = this;
      // prerequisite(s)
      if( !this.options.url ) return;
      // get endpoints
      var identifiers = [];
      for(var i in domains){
        identifiers.push({ type: 'dns', value: domains[i] });
      }
      return new Promise((resolve, reject) => {
        self.requester.request(self.options.url, { identifiers: identifiers }, {
            kid: self.options.kid
            //resource: "newOrder",
            //agreement: "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
        }).then((res) => {
            if (res.statusCode != 201 && res.statusCode != 409) {
                throw new Error("Error registering: " + res.statusCode + " " + res.body);
            }
            // assume valid data
            self.url = res.headers['location'];

            var data = JSON.parse(res.body);
            self.data = data;
            resolve(res);
        }).catch((err) => {
			console.log("Error: " + err);
		});

        //.catch(err => res.status(400).send("User- query promise was rejected." + res.body));

      });

    }

    auth( domain ){
      var self = this;

      return new Promise((resolve, reject) => {
        // prerequisite(s)
        // - can authorize only one domain at a time
        if(typeof domain !== "string") return reject("Not a valid domain to authorize");
        // -
        if( !self.data.identifiers ) return reject("Order has no domains to authorize");
        // loop through the order's identifiers
        var identifiers = self.data.identifiers;
        var match = false;
        for(var i in identifiers){
        if( identifiers[i].value !== domain ) continue;
        match = i;
        }
        if( !match ) return reject("Not a valid domain to authorize");

        // get the authorize url
        var url = self.data.authorizations[match];

        self.requester.request(url, "", {
              kid: self.options.kid
        }).then((res) => {
            // #1 FIX: the order of the identifiers don't always match the order of the authorizations
            let data = JSON.parse(res.body);
	    // error control
	    if( !data.identifier ){
    		console.log(data);
    		// continue...
		self.auth( domain ).then(resolve);
	    } else if( domain != data.identifier.value ){
                var valid = false;
                for(var j in identifiers){
                    if( identifiers[j].value !== data.identifier.value ) continue;
                    valid = j;
                }
                // reorder
                self.data.authorizations[match] = self.data.authorizations[valid];
                self.data.authorizations[valid] = url;
                // try again
                //console.log("try again:", domain);
                self.auth( domain ).then(resolve);
            } else {
                //console.log("domain ok...");
                resolve(res);
            }
        });
      });
    }

    finalize( cert ){
        var self = this;
        // prerequisite(s)
        if( !this.data.finalize ) return console.log({ error: "Finalize URL missing"});
        return this.requester.request( this.data.finalize, {
            csr: cert,
        }, { kid: self.options.kid }).then((result) => {
          return result;
        });
    }
}

module.exports = ACMEOrder;
