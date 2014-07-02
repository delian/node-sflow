/**
 * Created by delian
 */
var debug = require('debug')('sflow');
var dgram = require('dgram');
var Packet = require('./lib/packet');



function sflow(cb) {
    if (!(this instanceof sflow)) return new sflow(cb);

    var me = this;
    this.templates = {};

    this.server = dgram.createSocket('udp4');
    this.server.on('message', function (msg, rinfo) {
        debug('got a packet');
        var packet = new Packet(msg);
        if (cb) {
            packet.on('flow', function (flow) {
                debug('gow a flow %d from packet with sequence %d', flow.seqNum, packet.header.sequence);
                cb({header:packet.header, rinfo:rinfo, flow:flow});
            });
        }
    });

    this.listen = function(port) {
        setTimeout(function() {
            me.server.bind(port);
        },50);
    }
}


module.exports = sflow;