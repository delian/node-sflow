/**
 * Created by delian
 */
var debug = require('debug')('sflow');
var dgram = require('dgram');

function ipv4decode(buf) {
    var ip = buf.readUInt32BE(0);
    return (parseInt(ip/16777216)%256)+"."+(parseInt(ip/65536)%256)+"."+(parseInt(ip/256)%256)+"."+(ip%256);
}

function ipv6decode(buf) {
    return buf.toString('hex',0,16);
}

function sflow(cb) {
    if (!(this instanceof sflow)) return new sflow(cb);

    var me = this;
    this.templates = {};

    this.server = dgram.createSocket('udp4');
    this.server.on('message',function(msg,rinfo) {

        function readFlowRecords(buf) {
            var out = [];

            var n = buf.readUInt32BE(0);
            var b,i;

            for (buf = buf.slice(4);n;n--) {
                var flow = {};
                flow.format = buf.readUInt32BE(0);
                flow.enterprise = parseInt(flow.format/4096);
                flow.format = flow.format%4096;
                flow.length = buf.readUInt32BE(4);
                //flow.data = buf.slice(8,8+flow.length);
                if(flow.enterprise !== 0) {
                    debug('unknown enterprise', flow);
                    flow.type='unknown';
                    flow.data = buf.slice(8, 8+flow.length);
                }
                switch (flow.format) {
                    case 1:
                        flow.type = "raw";
                        flow.protocol = buf.readUInt32BE(8);
                        flow.protocolText = [null,"ethernet",null,null,null,null,null,null,null,null,null,"IPv4","IPv6"][flow.protocol]||"unknown";
                        flow.frameLen = buf.readUInt32BE(12);
                        flow.frameStripped = buf.readUInt32BE(16);
                        flow.hdrSize = buf.readUInt32BE(20);
                        flow.header = buf.slice(24,24+flow.hdrSize);
                        break;
                    case 2:
                        flow.type = "ethernet";
                        flow.frameLen = buf.readUInt32BE(8);
                        flow.srcMac = buf.toString('hex',12,18);
                        flow.dstMac = buf.toString('hex',20,26);
                        flow.frameType = buf.readUInt32BE(28);
                        break;
                    case 3:
                        flow.type = "IPv4";
                        flow.pktLen = buf.readUInt32BE(8);
                        flow.ipProto = buf.readUInt32BE(12);
                        flow.srcIp = ipv4decode(buf.slice(16));
                        flow.dstIp = ipv4decode(buf.slice(20));
                        flow.srcPort = buf.readUInt32BE(24);
                        flow.dstPort = buf.readUInt32BE(28);
                        flow.tcpFlags = buf.readUInt32BE(32);
                        flow.tos = buf.readUInt32BE(36);
                        break;
                    case 4:
                        flow.type = "IPv6";
                        flow.pktLen = buf.readUInt32BE(8);
                        flow.ipNextHeader = buf.readUInt32BE(12);
                        flow.srcIp = ipv6decode(buf.slice(16));
                        flow.dstIp = ipv6decode(buf.slice(32));
                        flow.srcPort = buf.readUInt32BE(48);
                        flow.dstPort = buf.readUInt32BE(52);
                        flow.tcpFlags = buf.readUInt32BE(56);
                        flow.ipPriority = buf.readUInt32BE(60);
                        break;
                    case 1001:
                        flow.type = "extendedSwitch";
                        flow.srcVlan = buf.readUInt32BE(8);
                        flow.srcPriority = buf.readUInt32BE(12);
                        flow.dstVlan = buf.readUInt32BE(16);
                        flow.dstPriority = buf.readUInt32BE(20);
                        break;
                    case 1002:
                        flow.type = "extendedRouter";
                        flow.ipVersion = buf.readUInt32BE(8);
                        flow.ipNextHop = flow.ipVersion==2?ipv6decode(buf.slice(12)):ipv4decode(buf.slice(12));
                        flow.srcMaskLen = buf.readUInt32BE(flow.ipVersion*16);
                        flow.dstMaskLen = buf.readUInt32BE(4+flow.ipVersion*16);
                        break;
                    case 1003:
                        flow.type = "extendedGateway";
                        b = buf.slice(8);
                        flow.ipVersion = b.readUInt32BE(0);
                        flow.ipNextHop = flow.ipVersion==2?ipv6decode(b.slice(4)):ipv4decode(b.slice(4));
                        b = b.slice(flow.ipVersion*16-8);
                        flow.routerAs = b.readUInt32BE(0);
                        flow.srcAs = b.readUInt32BE(4);
                        flow.srcPeerAs = b.readUInt32BE(8);
                        flow.dstAsPath = [];
                        for (i = b.readUInt32BE(12),b=b.slice(16);i;i--) {
                            var as = {};
                            as.type = b.readUInt32BE(0);
                            as.typeText = [null,"as-set","sequence"][as.type]||"unknown";
                            as.path = [];
                            var x = b.readUInt32BE(4);
                            for (b = b.slice(8);x;x--) { as.path.push(b.readUInt32BE(0));b = b.slice(4); }
                            flow.dstAsPath.push(as);
                        }
                        flow.community = [];
                        for (i = b.readUInt32BE(0),b= b.slice(4);i;i--) { flow.community.push(b.readUInt32BE(0)); b=b.slice(4); }
                        flow.localPref = b.readUInt32BE(0);
                        break;
                    case 1004:
                        flow.type = "extendedUser";
                        flow.srcCharset = buf.readUInt32BE(8);
                        flow.srcUserLen = buf.readUInt32BE(12);
                        flow.srcUser = buf.toString('utf8',16,16+flow.srcUserLen);
                        b = buf.slice(16+flow.srcUserLen);
                        flow.dstCharset = b.readUInt32BE(0);
                        flow.dstUserLen = b.readUInt32BE(4);
                        flow.dstUser = b.toString('utf8',8,8+flow.dstUserLen);
                        break;
                    case 1005:
                        flow.type = "extendedUrl";
                        flow.direction = buf.readUInt32BE(8);
                        flow.directionText = [null,"src","dest"][flow.direction]||"unknown";
                        flow.urlLen = buf.readUInt32BE(12);
                        flow.url = buf.toString('utf8',16,16+flow.urlLen);
                        b = buf.slice(16+flow.urlLen);
                        flow.hostLen = b.readUInt32BE(0);
                        flow.host = buf.toString('utf8',4,4+flow.hostLen);
                        break;
                    case 1006:
                        flow.type = "extendedMpls";
                        b = buf.slice(8);
                        flow.ipVersion = b.readUInt32BE(0);
                        flow.ipNextHop = flow.ipVersion==2?ipv6decode(b.slice(4)):ipv4decode(b.slice(4));
                        b = b.slice(16*flow.ipVersion-8);
                        flow.mplsInStackLen = b.readUInt32BE(0);
                        flow.mplsInStack = [];
                        for (i=flow.mplsInStackLen,b= b.slice(4);i;i--) {
                            flow.mplsInStack.push(b.readUInt32BE(0));b = b.slice(4);
                        }
                        flow.mplsOutStackLen = b.readUInt32BE(0);
                        flow.mplsOutStack = [];
                        for (i=flow.mplsOutStackLen,b= b.slice(4);i;i--) {
                            flow.mplsOutStack.push(b.readUInt32BE(0));b = b.slice(4);
                        }
                        break;
                    case 1007:
                        flow.type = "extendedNat";
                        b = buf.slice(8);
                        flow.ipVersionSrc = b.readUInt32BE(0);
                        flow.ipSrcAddr = flow.ipVersionSrc==2?ipv6decode(b.slice(4)):ipv4decode(b.slice(4));
                        b = buf.slice(flow.ipVersionSrc*16-8);
                        flow.ipVersionDst = b.readUInt32BE(0);
                        flow.ipDstAddr = flow.ipVersionDst==2?ipv6decode(b.slice(4)):ipv4decode(b.slice(4));
                        break;
                    case 1008:
                        flow.type = "extendedMplsTunnel";
                        b = buf.slice(8);
                        i = b.readUInt32BE(0);
                        flow.tunnelName = b.toString('utf8',4,4+i);
                        b = b.slice(4+i);
                        flow.tunnelId = b.readUInt32BE(0);
                        flow.tunnelCos = b.readUInt32BE(4);
                        break;
                    case 1009:
                        flow.type = "extendedMplsVc";
                        b = buf.slice(8);
                        i = b.readUInt32BE(0);
                        flow.vcName = b.toString('utf8',4,4+i);
                        b = b.slice(4+i);
                        flow.vcId = b.readUInt32BE(0);
                        flow.vcCos = b.readUInt32BE(4);
                        break;
                    case 1010:
                        flow.type = "extendedMplsFec";
                        b = buf.slice(8);
                        i = b.readUInt32BE(0);
                        flow.mplsFTNDescr = b.toString('utf8',4,4+i);
                        b = b.slice(4+i);
                        flow.mplsFTNMask = b.readUInt32BE(0);
                        break;
                    case 1011:
                        flow.type = "extendedMplsLvpFec";
                        flow.mplsFecAddrPreﬁxLength = buf.readUInt32BE(8);
                        break;
                    case 1012:
                        flow.type = "extendedVlanTunnel";
                        flow.vlanStackLen = buf.readUInt32BE(8);
                        flow.vlanStack = [];
                        for (i=flow.vlanStackLen,b=buf.slice(12);i;i--) {
                            flow.vlanStack.push(b.readUInt32BE(0)); b = b.slice(4);
                        }
                        break;
                    default:
                        console.log('unknown format',flow);
                        throw new Error('unknown format');
                }

                out.push(flow);
                buf = buf.slice(8+flow.length);
            }

            return out;
        }

        function readCounterRecords(buf) {
            var out = [];

            var n = buf.readUInt32BE(0);

            for (buf = buf.slice(4);n;n--) {
                var cnt = {};
                cnt.format = buf.readUInt32BE(0);
                cnt.length = buf.readUInt32BE(4);
                //cnt.data = buf.slice(8,8+flow.length);

                switch (cnt.format) {
                    case 1:
                        cnt.ifIndex = buf.readUInt32BE(8);
                        cnt.ifType = buf.readUInt32BE(12);
                        cnt.ifSpeed = buf.readUInt32BE(16);
                        cnt.ifDirection = buf.readUInt32BE(20);
                        cnt.ifDirectionText = [null,"full-duplex","half-duplex","in","out"][cnt.ifDirection]||"unknown";
                        cnt.ifStatus = buf.readUInt32BE(24);
                        cnt.ifStatusAdmin = (cnt.ifStatus&1)?"up":"down";
                        cnt.ifStatusOper = (cnt.ifStatus&2)?"up":"down";
                        cnt.ifInOctets = buf.readUInt32BE(28)*0x100000000 + buf.readUInt32BE(32);
                        cnt.ifInUcastPkts = buf.readUInt32BE(36);
                        cnt.ifInMulticastPkts = buf.readUInt32BE(40);
                        cnt.ifInBroadcastPkts = buf.readUInt32BE(44);
                        cnt.ifInDiscards = buf.readUInt32BE(48);
                        cnt.ifInErrors = buf.readUInt32BE(52);
                        cnt.ifInUnknownProtos = buf.readUInt32BE(56);
                        cnt.ifOutOctets = buf.readUInt32BE(60)*0x100000000 + buf.readUInt32BE(64);
                        cnt.ifOutUcastPkts = buf.readUInt32BE(68);
                        cnt.ifOutBroadcastPkts = buf.readUInt32BE(72);
                        cnt.ifOutDiscards = buf.readUInt32BE(76);
                        cnt.ifOutErrors = buf.readUInt32BE(80);
                        cnt.ifPromiscousMode = buf.readUInt32BE(84);
                        break;
                    case 2:
                        cnt.dot3StatsAlignmentErrors = buf.readUInt32BE(8);
                        cnt.dot3StatsFCSErrors = buf.readUInt32BE(12);
                        cnt.dot3StatsSingleCollisionFrames = buf.readUInt32BE(16);
                        cnt.dot3StatsMultipleCollisionFrames = buf.readUInt32BE(20);
                        cnt.dot3StatsSQETestErrors = buf.readUInt32BE(24);
                        cnt.dot3StatsDeferredTransmissions = buf.readUInt32BE(28);
                        cnt.dot3StatsLateCollisions = buf.readUInt32BE(32);
                        cnt.dot3StatsExcessiveCollisions = buf.readUInt32BE(36);
                        cnt.dot3StatsInternalMacTransmitErrors = buf.readUInt32BE(40);
                        cnt.dot3StatsCarrierSenseErrors = buf.readUInt32BE(44);
                        cnt.dot3StatsFrameTooLongs = buf.readUInt32BE(48);
                        cnt.dot3StatsInternalMacReceiveErrors = buf.readUInt32BE(52);
                        cnt.dot3StatsSymbolErrors = buf.readUInt32BE(56);
                        break;
                    case 3:
                        cnt.dot5StatsLineErrors = buf.readUInt32BE(8);
                        cnt.dot5StatsBurstErrors = buf.readUInt32BE(12);
                        cnt.dot5StatsACErrors = buf.readUInt32BE(16);
                        cnt.dot5StatsAbortTransErrors = buf.readUInt32BE(20);
                        cnt.dot5StatsInternalErrors = buf.readUInt32BE(24);
                        cnt.dot5StatsLostFrameErrors = buf.readUInt32BE(28);
                        cnt.dot5StatsReceiveCongestions = buf.readUInt32BE(32);
                        cnt.dot5StatsFrameCopiedErrors = buf.readUInt32BE(36);
                        cnt.dot5StatsTokenErrors = buf.readUInt32BE(40);
                        cnt.dot5StatsSoftErrors = buf.readUInt32BE(44);
                        cnt.dot5StatsHardErrors = buf.readUInt32BE(48);
                        cnt.dot5StatsSignalLoss = buf.readUInt32BE(52);
                        cnt.dot5StatsTransmitBeacons = buf.readUInt32BE(56);
                        cnt.dot5StatsRecoverys = buf.readUInt32BE(60);
                        cnt.dot5StatsLobeWires = buf.readUInt32BE(64);
                        cnt.dot5StatsRemoves = buf.readUInt32BE(68);
                        cnt.dot5StatsSingles = buf.readUInt32BE(72);
                        cnt.dot5StatsFreqErrors = buf.readUInt32BE(76);
                        break;
                    case 4:
                        cnt.dot12InHighPriorityFrames = buf.readUInt32BE(8);
                        cnt.dot12InHighPriorityOctets = buf.readUInt32BE(12)*0x100000000 + buf.readUInt32BE(16);
                        cnt.dot12InNormPriorityFrames = buf.readUInt32BE(20);
                        cnt.dot12InNormPriorityOctets = buf.readUInt32BE(24)*0x100000000 + buf.readUInt32BE(28);
                        cnt.dot12InIPMErrors = buf.readUInt32BE(32);
                        cnt.dot12InOversizeFrameErrors = buf.readUInt32BE(36);
                        cnt.dot12InDataErrors = buf.readUInt32BE(40);
                        cnt.dot12InNullAddressedFrames = buf.readUInt32BE(44);
                        cnt.dot12OutHighPriorityFrames = buf.readUInt32BE(48);
                        cnt.dot12OutHighPriorityOctets = buf.readUInt32BE(52)*0x100000000 + buf.readUInt32BE(56);
                        cnt.dot12TransitionIntoTrainings = buf.readUInt32BE(60);
                        cnt.dot12HCInHighPriorityOctets = buf.readUInt32BE(64)*0x100000000 + buf.readUInt32BE(68);
                        cnt.dot12HCInNormPriorityOctets = buf.readUInt32BE(72)*0x100000000 + buf.readUInt32BE(76);
                        cnt.dot12HCOutHighPriorityOctets = buf.readUInt32BE(80)*0x100000000 + buf.readUInt32BE(84);
                        break;
                    case 5:
                        cnt.vlan_id = buf.readUInt32BE(8);
                        cnt.octets = buf.readUInt32BE(12)*0x100000000 + buf.readUInt32BE(16);
                        cnt.ucastPkts = buf.readUInt32BE(20);
                        cnt.multicastPkts = buf.readUInt32BE(24);
                        cnt.broadcastPkts = buf.readUInt32BE(28);
                        cnt.discards = buf.readUInt32BE(32);
                        break;
                    case 1001:
                        cnt.cpuPerc5s = buf.readUInt32BE(8);
                        cnt.cpuPerc1m = buf.readUInt32BE(12);
                        cnt.cpuPerc5m = buf.readUInt32BE(16);
                        cnt.totalMem = buf.readUInt32BE(20)*0x100000000 + buf.readUInt32BE(24);
                        cnt.freeMem = buf.readUInt32BE(28)*0x100000000 + buf.readUInt32BE(32);
                        break;
                    default:
                        console.log('unknown format',cnt);
                        throw new Error('unknown format');
                }

                out.push(cnt);
                buf = buf.slice(8+cnt.length);
            }

            return out;
        }

        var buf = msg;
        var hdr = {};
        var o = { rinfo: rinfo, header: hdr, flow: {} };

        hdr.sflowVersion = buf.readUInt32BE(0);
        hdr.ipVersion = buf.readUInt32BE(4);
        hdr.ipVersionText = [null,"IPv4","IPv6"][hdr.ipVersion]||"Unknown";

        if (hdr.sflowVersion == 5 && (hdr.ipVersion == 1 || hdr.ipVersion == 2)) {
            if (hdr.ipVersion == 1) {
                hdr.ipAddress = ipv4decode(buf.slice(8));
                buf = buf.slice(12);
            } else {
                hdr.ipAddress = ipv6decode(buf.slice(8));
                buf = buf.slice(24);
            }

            hdr.subAgentId = buf.readUInt32BE(0);
            hdr.sequence = buf.readUInt32BE(4);
            hdr.uptimeMS = buf.readUInt32BE(8);
            hdr.samples = buf.readUInt32BE(12);

            buf = buf.slice(16);

            for (var n = hdr.samples;n;n--) {
                var sHdr = buf.readUInt32BE(0);
                o.flow = {};
                o.flow.enterprise = parseInt(sHdr/4096);
                o.flow.format = sHdr%4096;
                o.flow.length = buf.readUInt32BE(4);

                if (o.flow.enterprise>0) {
                    console.log('Unknown enterprise type',o);
                    throw new Error('Unknown enterprise type');
                }

                o.flow.seqNum = buf.readUInt32BE(8);

                switch (o.flow.format) {
                    case 1:
                        o.flow.sourceIdIndex = buf.readUInt32BE(12) % 0x1000000;
                        o.flow.sourceIdType = parseInt(buf.readUInt32BE(12) / 0x1000000);
                        o.flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][o.flow.sourceIdType]||"Unknown";
                        o.flow.samplingRate = buf.readUInt32BE(16);
                        o.flow.samplePool = buf.readUInt32BE(20);
                        o.flow.sampleDrops = buf.readUInt32BE(24);
                        o.flow.input = buf.readUInt32BE(28);
                        o.flow.output = buf.readUInt32BE(32);
                        o.flow.records = readFlowRecords(buf.slice(36));
                        break;
                    case 2:
                        o.flow.sourceIdIndex = buf.readUInt32BE(12) % 0x1000000;
                        o.flow.sourceIdType = parseInt(buf.readUInt32BE(12) / 0x1000000);
                        o.flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][o.flow.sourceIdType]||"Unknown";
                        o.flow.counters = readCounterRecords(buf.slice(16));
                        break;
                    case 3:
                        o.flow.sourceIdType = buf.reasUInt32BE(12);
                        o.flow.sourceIdIndex = buf.readUInt32BE(16);
                        o.flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][o.flow.sourceIdType]||"Unknown";
                        o.flow.samplingRate = buf.readUInt32BE(20);
                        o.flow.samplePool = buf.readUInt32BE(24);
                        o.flow.sampleDrops = buf.readUInt32BE(28);
                        o.flow.inputFormat = buf.readUInt32BE(32);
                        o.flow.input = buf.readUInt32BE(36);
                        o.flow.outputFormat = buf.readUInt32BE(40);
                        o.flow.output = buf.readUInt32BE(44);
                        o.flow.records = readFlowRecords(buf.slice(48));
                        break;
                    case 4:
                        o.flow.sourceIdType = buf.reasUInt32BE(12);
                        o.flow.sourceIdIndex = buf.readUInt32BE(16);
                        o.flow.sourceIdTypeText = ["ifIndex","smonVlanDataSource","entPhysicalEntry"][o.flow.sourceIdType]||"Unknown";
                        o.flow.counters = readCounterRecords(buf.slice(20));
                        break;
                    default:
                        console.log('Unknown format type',o);
                        throw new Error('Unknown format type');
                }

                if (cb) cb(o); // Do the callback per flow

                buf = buf.slice(o.flow.length+8);
            }
        } else console.log('Unknown packet',o);

    });

    this.listen = function(port) {
        setTimeout(function() {
            me.server.bind(port);
        },50);
    }
}

module.exports = sflow;