"use strict";

module.exports = function(value, encoding) {
    if (!(value instanceof Buffer)) {
        value = Buffer.from(value, encoding); //old: new Buffer(value, encoding);
    }
    return value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
