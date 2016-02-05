node-sflow
==========

SFlow compatible library

The library is still under development, please be careful! It has been tested with Extreme XOS only! Please raise issues in case of a problem!

## Usage

The usage of the Sflow collector library is very very simple. You just have to do something like this:


    var Collector = require('node-sflow');

    Collector(function(flow) {
        console.log(flow);
    }).listen(3000);


Keep in mind that even SFlow is a very powerful protocol (in many cases better than NetFlow, even if it is compared to NetFlow version 9) the implementation of the protocol is usually very limited by the hardware vendor.

This module only decodes to JSON the SFlow information provided by the SFlow source. If that is a decent source, the packet information, including L2, L3, L4 properties will be present as SFlow properties and you will have it decoded to JSON by this module.

However, many simple Ethernet switchies does not really implement SFlow. They just use it as a transport protocol and just encapsulate (usually the first 64 bytes of an) Ethernet packet on top of SFlow container and then send it to the collector. 
If your case is this one, then you will just receive Ethernet packet as raw data and you will not have the L2, L3, L4 properties decoded and you have to decode the Ethernet packet on your own.

Luckily, decoding raw Ethernet (or other) packets into JSON is realtively easy task, as there are a lot of NPM modules you could use to do that. Node.JS NPM provides you with a lot of helpful tools for it. I am sure you will find the best one fitting your needs.

If you are confused, you can look at this simple example, where I use the pcap module to decode raw ethernet packets received over SFlow (the following example uses the pcap module for Node.JS 0.12 to decode the ethernet fames):


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


In the above example, I use an integrated feature in the node-pcap module to decode the raw packet content. However, node-pcap module currently works only with Node.JS 0.10-0.12 and do not support the new C++ interface introduced in Node.JS 4 and 5. If you want to use Node.JS 4 and 5, try node-pcap2 module there. The API is a bit different (the decoder expects PCAP header too), but is not as much different. The following example works with node-pcap2 module for Node 4 and 5:


    var Collector = require('node-sflow');
    var pcap = require('pcap2');
    Collector(function(flow) {
        if (flow && flow.flow.records && flow.flow.records.length>0) {
            flow.flow.records.forEach(function(n) {
                if (n.type == 'raw') {
                    if (n.protocolText == 'ethernet') {
                        var pcapDummyHeader = new Buffer(16);
                        pcapDummyHeader.writeUInt32LE((new Date()).getTime()/1000,0); // Dummy time, you can take it from the sflow if you like
                        pcapDummyHeader.writeUInt32LE((new Date()).getTime()%1000,4);
                        pcapDummyHeader.writeUInt32LE(n.header.length,8);
                        pcapDummyHeader.writeUInt32LE(n.frameLen,12);
                        var pkt = pcap.decode.packet({
                           buf: n.header,
                           header: pcapDummyHeader,
                           link_type: 'LINKTYPE_ETHERNET'
                        });
                        if (pkt.ethertype!=2048) return; // Check if it is IPV4 packet
                        console.log('VLAN',pkt.vlan,'Packet',pkt.payload.IPv4)
                    }
                }
            });
        }
    }).listen(3000);

