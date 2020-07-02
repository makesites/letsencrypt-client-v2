"use strict";

const request = require("request");

module.exports = function(url, options) {
    // fallback(s)
    url = url || "";
    options = options || {};
    // prerequisite(s)
    if( url == "" ) return console.log("No URL provided");
    if (url.substr(0, 1) == "/") url = "https://acme-v02.api.letsencrypt.org" + url;
    options.url = url;
    return new Promise((resolve, reject) => {
        //console.log("requesting " + url);
        options.headers = options.headers || {};
        options.headers.Accept = 'application/json';
        options.headers['Content-Type']  = "application/jose+json";
        request(Object.assign({ url: url }, options), (error, response, body) => {
            if (error) return reject(error);
            //console.log({headers: response.headers, statusCode: response.statusCode, body: body});
            resolve({headers: response.headers, statusCode: response.statusCode, body: body});
        });
    });
}
