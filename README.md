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

This module decodes to JSON the SFlow information provided by the SFlow source. If that is a decent source, the packet information could be already decoded in sflow properties and you will receive it decoded to JSON by this module.

However, many simple Ethernet switchies does not really implement SFlow. They just encapsulate (usually the first 64 bytes of an) Ethernet packet into SFlow container and send it to the collector. If you have that case, then you will get the Ethernet packet as data and its properties will not be decided by this SFlow module as the SFlow collector receives packets as "raw record" which does not contain properties as IP addresses, ports, etc, and you have to decode the packet on your own.

If you receive raw packets you have to decode the packet separately if you want to access and read its properties!

However, the decode if raw packet header is not a complex thing. Node.JS NPM provides you with a lot of helpful tools for it. I am sure you will find the best one fitting your needs.

If you are confused, you can look at this simple example, where I use the pcap module to decode raw ethernet packets received over SFlow:


    var Collector = require('node-sflow');
    var pcap = require('pcap2');
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

NOTE:
In the given example above I am using pcap2 node module! It is basically the same as the pcap module, although it is patched to support the new C++ interface within Node.JS 4 and 5. If you are using Node 4/5+ you have to use pcap2. If you are using Node 0.09-0.12, you have to use the pcap module to decode raw ethernet packet.
