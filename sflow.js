/**
 * Created by delian
 */

var dgram = require('dgram');

function sflow(cb) {
    if (!(this instanceof sflow)) return new sflow(cb);

    var me = this;
    this.templates = {};

    this.server = dgram.createSocket('udp4');
    this.server.on('message',function(msg,rinfo) {
        console.log('rinfo',rinfo);
        if (cb) cb(msg);
    });
    this.listen = function(port) {
        setTimeout(function() {
            me.server.bind(port);
        },50);
    }
}

module.exports = sflow;