//
//  String+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension String {
    var ipv4address: UInt? {
        let octets = self.split(separator: ".")
        guard octets.count == 4 else { return nil }
        guard let octet1 = UInt8(octets[0]) else { return nil }
        guard let octet2 = UInt8(octets[1]) else { return nil }
        guard let octet3 = UInt8(octets[2]) else { return nil }
        guard let octet4 = UInt8(octets[3]) else { return nil }
        let answer: UInt = UInt(octet1) * 256 * 256 * 256 + UInt(octet2) * 256 * 256 + UInt(octet3) * 256 + UInt(octet4)
        return answer
    }
    var nxosTcpPort: UInt? {
        switch self {
        case "bgp":
            return 179
        case "chargen":
            return 19
        case "cmd":
            return 514
        case "daytime":
            return 13
        case "discard":
            return 9
        case "domain":
            return 53
        case "drip":
            return 3949
        case "echo":
            return 7
        case "exec":
            return 512
        case "finger":
            return 79
        case "ftp":
            return 21
        case "ftp-data":
            return 20
        case "gopher":
            return 7
        case "hostname":
            return 11
        case "ident":
            return 113
        case "irc":
            return 194
        case "klogin":
            return 543
        case "kshell":
            return 544
        case "login":
            return 513
        case "lpd":
            return 515
        case "nntp":
            return 119
        case "pim-auto-rp":
            return 496
        case "pop2":
            return 19
        case "pop3":
            return 11
        case "smtp":
            return 25
        case "sunrpc":
            return 111
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "telnet":
            return 23
        case "time":
            return 37
        case "uucp":
            return 54
        case "whois":
            return 43
        case "www":
            return 80
        default:
            return nil
        }
    }
    var nxosUdpPort: UInt? {
        switch self {
        case "biff":
            return 512
        case "bootpc":
            return 68
        case "bootps":
            return 67
        case "discard":
            return 9
        case "dnsix":
            return 195
        case "domain":
            return 53
        case "echo":
            return 7
        case "isakmp":
            return 5
        case "mobile-ip":
            return 434
        case "nameserver":
            return 42
        case "netbios-dgm":
            return 138
        case "netbios-ns":
            return 137
        case "netbios-ss":
            return 139
        case "non500-isakmp":
            return 45
        case "ntp":
            return 123
        case "pim-auto-rp":
            return 496
        case "rip":
            return 52
        case "snmp":
            return 161
        case "snmptrap":
            return 162
        case "sunrpc":
            return 111
        case "syslog":
            return 514
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "tftp":
            return 69
        case "time":
            return 37
        case "who":
            return 513
        case "xdmcp":
            return 177
        default:
            return nil
        }
    }
    var iosXrTcpPort: UInt? {
        switch self {
        case "bgp":
            return 179
        case "chargen":
            return 19
        case "cmd":
            return 514
        case "daytime":
            return 13
        case "discard":
            return 9
        case "domain":
            return 53
        case "echo":
            return 7
        case "exec":
            return 512
        case "finger":
            return 79
        case "ftp":
            return 21
        case "ftp-data":
            return 20
        case "gopher":
            return 7
        case "hostname":
            return 11
        case "ident":
            return 113
        case "irc":
            return 194
        case "klogin":
            return 543
        case "kshell":
            return 544
        case "login":
            return 513
        case "lpd":
            return 515
        case "nntp":
            return 119
        case "pim-auto-rp":
            return 496
        case "pop2":
            return 19
        case "pop3":
            return 11
        case "smtp":
            return 25
        case "sunrpc":
            return 111
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "telnet":
            return 23
        case "time":
            return 37
        case "uucp":
            return 54
        case "whois":
            return 43
        case "www":
            return 80
        default:
            return nil
        }
    }

    var iosXrUdpPort: UInt? {
        switch self {
        case "biff":
            return 512
        case "bootpc":
            return 68
        case "bootps":
            return 67
        case "discard":
            return 9
        case "dnsix":
            return 195
        case "domain":
            return 53
        case "echo":
            return 7
        case "isakmp":
            return 5
        case "mobile-ip":
            return 434
        case "nameserver":
            return 42
        case "netbios-dgm":
            return 138
        case "netbios-ns":
            return 137
        case "netbios-ss":
            return 139
        case "ntp":
            return 123
        case "pim-auto-rp":
            return 496
        case "rip":
            return 52
        case "snmp":
            return 161
        case "snmptrap":
            return 162
        case "sunrpc":
            return 111
        case "syslog":
            return 514
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "tftp":
            return 69
        case "time":
            return 37
        case "who":
            return 513
        case "xdmcp":
            return 177
        default:
            return nil
        }
    }

    func tcpPort(deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) -> UInt? {
        switch (deviceType,self) {
        case (.asa,"aol"):
            return 5190
        case (_,"bgp"):
            return 179
        case (.asa,"chargen"):
            return 19
        case (.asa,"citrix-ica"):
            return 1494
        case (_,"cmd"):
            return 514
        case (.asa,"ctiqbe"):
            return 2748
        case (.asa,"daytime"):
            return 13
        case (.asa,"discard"):
            return 9
        case (_,"domain"):
            return 53
        case (.asa,"echo"):
            return 7
        case (_,"exec"):
            return 512
        case (.asa,"finger"):
            return 79
        case (_,"ftp"):
            return 21
        case (_,"ftp-data"):
            return 20
        case (.asa,"gopher"):
            return 70
        case (.asa,"h323"):
            return 1720
        case (.asa,"hostname"):
            return 101
        case (_,"https"):
            return 443
        case (.asa,"ident"):
            return 113
        case (.asa,"imap4"):
            return 143
        case (.asa,"irc"):
            return 194
        case (.asa,"kerberos"):
            return 750
        case (.asa,"klogin"):
            return 543
        case (.asa,"ksh"):
            return 544
        case (.asa,"ldap"):
            return 389
        case (.asa,"ldaps"):
            return 636
        case (.asa,"lpd"):
            return 515
        case (.asa,"login"):
            return 513
        case (.asa,"lotusnotes"):
            return 1352
        case (_,"mms"):
            return 1755
        case (.asa,"netbios-ssn"):
            return 139
        case (.asa,"nntp"):
            return 119
        case (_,"nfs"):
            return 2049
        case (.asa,"pcanywhere-data"):
            return 5631
        case (.asa,"pim-auto-rp"):
            return 496
        case (.asa,"pop2"):
            return 109
        case (.asa,"pop3"):
            return 110
        case (.asa,"pptp"):
            return 1723
        case (_,"smtp"):
            return 25
        case (.asa,"sqlnet"):
            return 1521
        case (_,"ssh"):
            return 22
        case (.asa,"sunrpc"):
            return 111
        case (_,"tacacs"):
            return 49
        case (.asa,"talk"):
            return 517
        case (_,"telnet"):
            return 23
        case (.asa,"uucp"):
            return 540
        case (.asa,"whois"):
            return 43
        case (_,"www"):
            return 80
        default:
            return nil
        }
    }
    
    var asaIcmpType: UInt? {
        switch self {
        case "echo-reply":
            return 0
        case "unreachable":
            return 3
        case "source-quench":
            return 4
        case "redirect":
            return 5
        case "alternate-address":
            return 6
        case "echo":
            return 8
        case "router-advertisement":
            return 9
        case "router-solicitation":
            return 10
        case "time-exceeded":
            return 11
        case "parameter-problem":
            return 12
        case "timestamp-request":
            return 13
        case "timestamp-reply":
            return 14
        case "information-request":
            return 15
        case "information-reply":
            return 16
        case "address-mask-request":
            return 17
        case "address-mask-reply":
            return 18
        case "conversion-error":
            return 31
        case "mobile-redirect":
            return 32
        default:
            return nil
        }
    }
    func udpPort(deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) -> UInt? {
        switch (deviceType, self) {
        case (.asa,"biff"):
            return 512
        case (_,"bootpc"):
            return 68
        case (_,"bootps"):
            return 67
        case (.asa,"discard"):
            return 9
        case (.asa,"dnsix"):
            return 195
        case (.asa,"dns"):
            delegate?.report(severity: .warning, message: "ASA dns port is short for dnsix which is UDP/195, this is probably not what you want", delegateWindow: delegateWindow)
            return 195
        case (_,"domain"):
            return 53
        case (.asa,"echo"):
            return 7
        case (_,"isakmp"):    //TODO only on some platforms
            return 500
        case (.asa,"kerberos"):
            return 750
        //case (_,"ldap"):
            //return 389
        //case (_,"mms"):
            //return 1755
        case (_,"netbios-dgm"):
            return 138
        case (_,"netbios-ns"):
            return 137
        //case (_,"netbios-ss"):
            //return 139
        case (.ios,"non500-isakmp"), (.iosxe,"non500-isakmp"):   //TODO only on some platforms
            delegate?.report(severity: .warning, message: "non500-isakmp is only supported on some IOS platforms", delegateWindow: delegateWindow)
            return 4500
        case (.ios,"nfs"), (.iosxe,"nfs"),(.iosxr,"nfs"),(.nxos,"nfs"):
            return 2049
        case (_,"ntp"):
            return 123
        case (.asa,"pcanywhere-status"):
            return 5632
        case (.asa,"pim-auto-rp"):
            return 496
        case (.asa,"radius"):
            return 1645
        case (.asa,"radius-acct"):
            return 1646
        case (.asa,"rip"):
            return 520
        case (.asa,"secureid-udp"):
            return 5510

        case (_,"snmp"):
            return 161
        case (_,"snmptrap"):
            return 162
        case (.asa,"sunrpc"):
            return 111
        case (_,"syslog"):
            return 514
        case (_,"tacacs"):
            return 49
        case (.asa,"talk"):
            return 517
        case (.asa,"time"):
            return 37
        case (_,"tftp"):
            return 69
        case (_,"wccp"):
            return 2048
        case (.asa,"who"):
            return 513
        case (.asa,"xdmcp"):
            return 177
        default:
            return nil
        }
    }
/*    var asaUdpPort: UInt? {  //TODO check list
        switch self {
        case "bootpc":
            return 68
        case "bootps":
            return 67
        case "domain":
            return 53
        case "isakmp":    //TODO only on some platforms
            return 500
        case "ldap":
            return 389
        case "mms":
            return 1755
        case "netbios-dgm":
            return 138
        case "netbios-ns":
            return 137
        case "netbios-ss":
            return 139
        case "non500-isakmp":   //TODO only on some platforms
            return 4500
        case "nfs":
            return 2049
        case "ntp":
            return 123
        case "snmp":
            return 161
        case "snmptrap":
            return 162
        case "syslog":
            return 514
        case "tacacs":
            return 49
        case "tftp":
            return 69
        case "wccp":
            return 2048
        default:
            return nil
        }
    }*/

    var iosXrIpProtocol: UInt? {
        switch self {
        case "ahp":
            return 51
        case "eigrp":
            return 88
        case "esp":
            return 50
        case "gre":
            return 47
        case "icmp":
            return 1
        case "igmp":
            return 2
        case "igrp":
            return 9
        case "ip":
            return 0
        case "ipv4":
            return 0
        case "ipinip":
            return 94
        case "nos": // not a typo both ipinip and nos report 94
            return 94
        case "ospf":
            return 89
        case "pcp":
            return 108
        case "pim":
            return 103
        case "tcp":
            return 6
        case "udp":
            return 17
        default:
            return nil
        }
    }

    var nxosIpProtocol: UInt? {
        switch self {
        case "ahp":
            return 51
        case "eigrp":
            return 88
        case "esp":
            return 50
        case "gre":
            return 47
        case "icmp":
            return 1
        case "igmp":
            return 2
        case "ip":
            return 0
        case "nos":
            return 94
        case "ospf":
            return 89
        case "pcp":
            return 108
        case "pim":
            return 103
        case "tcp":
            return 6
        case "udp":
            return 17
        default:
            return nil
        }
    }
    
    
    //TODO UPDATE COPIED FROM IOSXR
    var iosIpProtocol: UInt? {
        switch self {
        case "ahp":
            return 51
        case "eigrp":
            return 88
        case "esp":   //TODO may not be supported all platforms
            return 50
        case "gre":
            return 47
        case "icmp":
            return 1
        case "igmp":
            return 2
        case "igrp":
            return 9
        case "ip":
            return 0
        case "ipv4":
            return 0
        case "ipinip":
            return 94
        case "nos": // not a typo both ipinip and nos report 94
            return 94
        case "ospf":
            return 89
        case "pcp":
            return 108
        case "pim":
            return 103
        case "tcp":
            return 6
        case "udp":
            return 17
        default:
            return nil
        }
    }

    //TODO UPDATE COPIED FROM IOSXR
    var iosTcpPort: UInt? {
        switch self {
        case "bgp":
            return 179
        case "chargen":
            return 19
        case "cmd":
            return 514
        case "daytime":
            return 13
        case "discard":
            return 9
        case "domain":
            return 53
        case "echo":
            return 7
        case "exec":
            return 512
        case "finger":
            return 79
        case "ftp":
            return 21
        case "ftp-data":
            return 20
        case "gopher":
            return 7
        case "hostname":
            return 11
        case "ident":
            return 113
        case "irc":
            return 194
        case "klogin":
            return 543
        case "kshell":
            return 544
        case "login":
            return 513
        case "lpd":
            return 515
        case "nfs":
            return 2049     //TODO checkthis
        case "nntp":
            return 119
        case "pim-auto-rp":
            return 496
        case "pop2":
            return 19
        case "pop3":
            return 11
        case "smtp":
            return 25
        case "ssh":    // TODO check this one
            return 22
        case "sunrpc":
            return 111
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "telnet":
            return 23
        case "time":
            return 37
        case "uucp":
            return 54
        case "whois":
            return 43
        case "www":
            return 80
        default:
            return nil
        }
    }
    
    //TODO UPDATE COPIED FROM IOSXR
    var iosUdpPort: UInt? {
        switch self {
        case "biff":
            return 512
        case "bootpc":
            return 68
        case "bootps":
            return 67
        case "discard":
            return 9
        case "dnsix":
            return 195
        case "domain":
            return 53
        case "echo":
            return 7
        case "isakmp":  //TODO warn not supported all ios
            return 500
        case "mobile-ip":
            return 434
        case "nameserver":
            return 42
        case "netbios-dgm":
            return 138
        case "netbios-ns":
            return 137
        case "netbios-ss":
            return 139
        case "non500-isakmp":  //TODO warn not supported all ios
            return 4500
        case "ntp":
            return 123
        case "pim-auto-rp":
            return 496
        case "rip":
            return 52
        case "snmp":
            return 161
        case "snmptrap":
            return 162
        case "sunrpc":
            return 111
        case "syslog":
            return 514
        case "tacacs":
            return 49
        case "talk":
            return 517
        case "tftp":
            return 69
        case "time":
            return 37
        case "who":
            return 513
        case "xdmcp":
            return 177
        default:
            return nil
        }
    }

    var asaIpProtocol: UInt? {  //TOD check list
        switch self {
        case "eigrp":
            return 88
        case "esp":     //TODO only on some platforms
            return 50
        case "gre":
            return 47
        case "icmp":
            return 1
        case "igmp":
            return 2
        case "ip":
            return 0
        case "ipnip":
            return 94
        case "ospf":
            return 89
        case "pim":
            return 103
        case "tcp":
            return 6
        case "udp":
            return 17
        default:
            return nil
        }
    }
    var asaPort: UInt? {
        if let portNumber = UInt(self) {
            if portNumber >= 0 && portNumber <= 65535 {
                return portNumber
            } else {
                return nil
            }
        } else {
            if let portNumber = self.tcpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                return portNumber
            } else if let portNumber = self.udpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                return portNumber
            } else {
                return nil
            }
        }
    }
}
