#!/usr/bin/env node
/*******************************************************************************
 * nodeKnock 0.2 by freddyb
 *      for nodeJS 0.2.5
 ******************************************************************************/

// Constants
HEADER_DEC = [78, 68, 75]; // ASCii 'NDK', by convention
    //XXX Attention: The header is in decimal. Not hex!
    //      length of HEADER must NEVER change.
DEBUG=false;

// Functions
function hex(i) {
    // turns 255 Integer to 'FF' String
    s = i.toString(16).toUpperCase();
    if (s.length == 1)
        s = '0'+s;
    return s;
}
function getTimestamp() {
    // 4 Byte representation of current timestamp in a hex-String Array
    // e.g. ['40','AB','49','31']
    ts = Math.floor((new Date()).getTime() / 1000);
    tsArr = [];
    tsArr[0] = Math.floor(ts / Math.pow(256,3)) % 256; //MSB
    tsArr[1] = Math.floor(ts / Math.pow(256,2)) % 256;
    tsArr[2] = Math.floor(ts / Math.pow(256,1)) % 256;
    tsArr[3] = Math.floor(ts / Math.pow(256,0)) % 256; //LSB
    return tsArr;
}
function chkTimeStamp(givenTs) {
    // Compare given Timestatmp with current
    THRESHOLD = 2; // request packet MUST NOT take longer than *these* to arrive
    cur = getTimestamp();
    if (givenTs[0] == cur[0] && givenTs[1] == cur[1] && givenTs[2] == cur[2]) {
            if ((cur[3] - givenTs[3]) < THRESHOLD)
                return true;
        }
    return false;
}
function doHash(ip, ts) {
    // sha1(client_ip + secret + timestamp')
    // client_ip: String //XXX BULLSHIT :)
    // secret ??
    // timestamp: integer
        tsInt = ts[0]*Math.pow(256,3) + ts[1]*Math.pow(256,2) + ts[2]*Math.pow(256,1) + ts[3];
    h = crypto.createHash('sha1');
    a = h.update(ip+config.secret+tsInt).digest('hex').toUpperCase();
    arr= [];
    for (i=0; i<(a.length/2); i++) {
        arr[i] = parseInt(a.substr(2*i,2), 16);
    }
    return arr; // output: decimal
}
function addIPtoWhitelist(ip) {
    //iptables -A INPUT -s <IP> -p tcp --dport 8000 -j ACCEPT
    argsAdd = ['-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', config['port'], '-j', 'ACCEPT'];
    argsDel = ['-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', config['port']', '-j', 'ACCEPT'];
    ipt = spawn('iptables', argsAdd);

    ipt.on('exit', function (code) {
        if (code !== 0) {
            sys.puts('ERROR: Could not run iptables to add '+ ip +' (' + code +')');
        }
        else {
            sys.puts("Added "+ip+" to the Whitelist!");
        }
    });
    setTimeout(delIPfromWhitelist, config['duration']*1000, argsDel, ip)
}
function delIPfromWhitelist(argsD, ip) {
    ipt = spawn('iptables', argsD);
    ipt.on('exit', function (code) {
        if (code !== 0) {
            sys.puts('ERROR: Could not REMOVE '+ip+' from iptables-whitelist (' + code +')');
        }
        else {
            sys.puts("Removed "+ip+" from the Whitelist!");
        }
    });
}

// Starting here
var fs = require("fs"), crypto = require("crypto");
var sys = require("sys"), pcap = require("pcap"), pcap_session;
var spawn = require('child_process').spawn,

cfg = fs.readFileSync('nodeKnock.cfg'); // synchronous in nodeJS. NUUUU :(
eval(cfg.toString());

if (!config.secret || !config.host || !config.port) {
    process.exit(1);
}
if (!config.duration)
    config.duration = 3600;

if (process.argv.length > 3) {
    sys.error("usage: simple_capture interface");
    process.exit(1);
}
pcap_session = pcap.createSession(process.argv[2], 'icmp'); // only capture icmp
sys.puts(pcap.lib_version);

// Print listening device with address
pcap_session.findalldevs().forEach(function (dev) {
    if (pcap_session.device_name === dev.name) {
        sys.print(dev.name + " ");
        if (dev.addresses.length > 0) {
            dev.addresses.forEach(function (address) {
                sys.print(address.addr + "/" + address.netmask);
            });
            sys.print("\n");
        } else {
            sys.print("no address\n");
        }
    }
});


pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    if (packet.link.ip.protocol_name == "ICMP") {
        if (packet.link.ip.icmp.type_desc != 'Echo Request') {
            return
        }
        if (DEBUG)
            sys.puts(pcap.print.packet(packet));
        if (typeof packet.link.ip.icmp.data != "undefined")
            d = packet.link.ip.icmp.data
        else { // once our pull-request is through, this else-part will be obsolete
            d = [];
            for (i=0; (offset+8+i) < raw_packet.pcap_header.caplen; i++) {
                d[i] = raw_packet[offset + 8 + i];
            }
        }
        // Find offset for HEADER
        offset = d.indexOf(HEADER_DEC[1])-1
        d = d.slice(offset);
        H=HEADER_DEC

        if (DEBUG)
            sys.puts(H[0] +'=='+ d[0] +', '+ H[1] +'=='+d[1] +', '+ H[2]+'=='+ d[2]);
        if (H[0] == d[0] && H[1] == d[1] && H[2] == d[2]) { // header present
            // bad luck *OR* there is a client asking us something. prblblty-strength:  3 bytes
            if (DEBUG)
                sys.puts("1) valid header recvd from "+ packet.link.ip.saddr);
            clientTS = [d[3], d[4], d[5], d[6]];
            if (chkTimeStamp(clientTS) === true) {
                if (DEBUG)
                    sys.puts("2) valid TS recvd from "+ packet.link.ip.saddr);
                // the provided timestamp is not too old: we're running out of bad luck, I guess ;)
                myHash = doHash(packet.link.ip.saddr, clientTS);

                chk = true;
                for (i=0; i<9; i++) {
                    /*XXX PROBLEM!
                     * linux ping(8) has a limited byte length, and after 9
                     * hash-bytes, we exceed it :(
                     */
                    if (myHash[i] != d[7+i]) {
                        chk = false;
                        break
                    }
                }
                if (chk === true) {
                    if (DEBUG)
                        sys.puts("valid hash, i.e. good request from "+ packet.link.ip.saddr);
                    addIPtoWhitelist(packet.link.ip.saddr);
                }
                else {
                    sys.puts("3) but hash is invalid :(")
                }
            }
            else {
                sys.puts('2) TS is crap :(');
            }
        }
        else if (DEBUG) {
            sys.puts('boring echo-request from ' + packet.link.ip.saddr);
        }
        if (DEBUG)
            sys.puts('icmp bytes ('+ d.length + '): ' +d.toString());
    }
});
