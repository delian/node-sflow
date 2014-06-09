node-sflow
==========

SFlow compatible library

The library is still under development, please be careful! It has been tested with Extreme XOS only! Please raise issues in case of problem!

## Usage

The usage of the Sflow collector library is very very simple. You just have to do something like this:


    var Collector = require('node-sflow');
    
    Collector(function(flow) {
        console.log(flow);
    }).listen(3000);


Keep in mind that even SFlow is very powerful protocol (better than NetFlow, even compared to NetFlow version 9) the implementation of it is usually very limited.
Most of the simplified Ethernet switches does not really implement the SFlow in its pure power. Instread they just use it to export sampled packet capture to the SFlow Collector.
Therefore the SFlow collector receives packets as "raw record" which does not contain properties as IP adresses, ports, etc, and you have to decode the packet on your own.

This SFlow library does not do that for you! If you receive raw packets you have to decode it on your own as the decoding of it is not part of the SFlow protocol and I like to keep the libraries simple and separated!

However, the decode if raw packet header is not a complex thing. Node.JS NPM provides you with a lot of helpful tools for it. I am sure you will find the best one fitting your needs.
If you are confused, you can look at this simple example:


    var Collector = require('node-sflow');
    var pcap = require('pcap');

    Collector(function(flow) {
        if (flow && flow.flow.records && flow.flow.records.length>0) {
            flow.flow.records.forEach(function(n) {
                if (n.type == 'raw') {
                    if (n.protocolText == 'ethernet') {
                        try {
                            var pkt = pcap.decode.ethernet(n.header, 0);
                            if (pkt.ethertype!=2048) return;
                            console.log('VLAN',pkt.vlan?pkt.vlan.id:'none','Packet',pkt.ip.protocol_name,pkt.ip.saddr,':',pkt.ip.tcp?pkt.ip.tcp.sport:pkt.ip.udp.sport,'->',pkt.ip.daddr,':',pkt.ip.tcp?pkt.ip.tcp.dport:pkt.ip.udp.dport)
                        } catch(e) { console.log(e); }
                    }
                }
            });
        }
    }).listen(3000);

