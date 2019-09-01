//
//  String+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

extension String {
    var ipv4address: UInt128? {
        let octets = self.split(separator: ".")
        guard octets.count == 4 else { return nil }
        guard let octet1 = UInt8(octets[0]) else { return nil }
        guard let octet2 = UInt8(octets[1]) else { return nil }
        guard let octet3 = UInt8(octets[2]) else { return nil }
        guard let octet4 = UInt8(octets[3]) else { return nil }
        
        //performance optimization
        //let answer: UInt128 = UInt128(octet1) * 256 * 256 * 256 + UInt128(octet2) * 256 * 256 + UInt128(octet3) * 256 + UInt128(octet4)
        let answer: UInt = (UInt(octet1) << 24) + (UInt(octet2) << 16) + (UInt(octet3) << 8) + UInt(octet4)
        return UInt128(answer)
    }
    var ipv6address: UInt128? {
        guard let ipv6 = IPv6Address(self) else { return nil }
        return ipv6.uint128
    }

    func tcpPort(deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) -> UInt? {
        switch (deviceType,self) {
        case (.asa,"aol"):
            return 5190
        case (_,"bgp"):
            return 179
        case (_,"chargen"):
            return 19
        case (.asa,"citrix-ica"):
            return 1494
        case (_,"cmd"):
            return 514
        case (.asa,"ctiqbe"):
            return 2748
        case (_,"daytime"):
            return 13
        case (_,"discard"):
            return 9
        case (_,"domain"):
            return 53
        case (.ios,"drip"),(.nxos,"drip"):
            return 3949
        case (_,"echo"):
            return 7
        case (.asa,"exec"),(.nxos,"exec"),(.iosxr,"exec"):
            return 512
        // some ios versions support exec
        case (_,"finger"):
            return 79
        case (_,"ftp"):
            return 21
        case (_,"ftp-data"):
            return 20
        case (_,"gopher"):
            return 70
        case (.asa,"h323"):
            return 1720
        case (_,"hostname"):
            return 101
        case (.asa,"https"):
            return 443
        case (.asa,"ident"),(.nxos,"ident"),(.iosxr,"ident"):
            return 113
        // some ios versions support ident
        case (.asa,"imap4"):
            return 143
        case (_,"irc"):
            return 194
        case (.asa,"kerberos"):
            return 750
        case (_,"klogin"):
            return 543
        case (.asa,"ksh"):
            return 544
        case (.ios,"kshell"),(.iosxr,"kshell"),(.nxos,"kshell"):
            return 544
        case (.asa,"ldap"):
            return 389
        case (.asa,"ldaps"):
            return 636
        case (.asa,"login"),(.nxos,"login"),(.iosxr,"login"):
            return 513
        // some ios versions upport login
        case (_,"lpd"):
            return 515
        case (.asa,"lotusnotes"):
            return 1352
        case (.asa,"mms"):
            return 1755
        case (.asa,"netbios-ssn"):
            return 139
        case (_,"nntp"):
            return 119
        case (.asa,"nfs"):
            return 2049
        case (.asa,"pcanywhere-data"):
            return 5631
        case (.asa,"pim-auto-rp"),(.nxos,"pim-auto-rp"),(.iosxr,"pim-auto-rp"):
            return 496
        //some ios versions support pim-auto-rp
        case (_,"pop2"):
            return 109
        case (_,"pop3"):
            return 110
        case (.asa,"pptp"):
            return 1723
        case (_,"smtp"):
            return 25
        case (.asa,"sqlnet"):
            return 1521
        case (.asa,"ssh"):
            return 22
        case (_,"sunrpc"):
            return 111
        case (.ios,"syslog"):
            return 514
        case (.asa,"tacacs"),(.nxos,"tacacs"),(.iosxr,"tacacs"):
            return 49
        // some ios versions support tacacs
        case (.ios,"tacacs-ds"):
            return 49
        case (_,"talk"):
            return 517
        case (_,"telnet"):
            return 23
        case (.ios,"time"),(.iosxr,"time"),(.nxos,"time"):
            return 37
        case (_,"uucp"):
            return 540
        case (_,"whois"):
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
        case (_,"biff"):
            return 512
        case (_,"bootpc"):
            return 68
        case (_,"bootps"):
            return 67
        case (_,"discard"):
            return 9
        case (_,"dnsix"):
            return 195
        case (_,"dns"):
            delegate?.report(severity: .warning, message: "DNS port is short for dnsix which is UDP/195, this is probably not what you want", delegateWindow: delegateWindow)
            return 195
        case (_,"domain"):
            return 53
        case (_,"echo"):
            return 7
        case (_,"isakmp"):    //TODO only on some platforms
            switch deviceType {
            case .asa, .nxos, .nxosv6, .arista, .iosxr:
                break
            case .ios,.iosv6:
                delegate?.report(severity: .warning, message: "isakmp port label is only supported on some ios platforms", delegateWindow: delegateWindow)
            }
            return 500
        case (.asa,"kerberos"):
            return 750
        //case (_,"ldap"):
            //return 389
        //case (_,"mms"):
            //return 1755
        case (.ios,"mobile-ip"),(.iosxr,"mobile-ip"),(.nxos,"mobile-ip"):
            return 434
        case (.ios,"nameserver"),(.iosxr,"nameserver"),(.nxos,"nameserver"):
            return 42
        case (_,"netbios-dgm"):
            return 138
        case (_,"netbios-ns"):
            return 137
        case (.nxos,"netbios-ss"):
            return 139
        case (.ios,"non500-isakmp"),(.nxos,"non500-isakmp"):
            return 4500
        //case (.ios,"nfs"), (.iosxe,"nfs"),(.iosxr,"nfs"),(.nxos,"nfs"):
        //    return 2049
        case (_,"ntp"):
            return 123
        case (.asa,"pcanywhere-status"):
            return 5632
        case (.asa,"pim-auto-rp"),(.nxos,"pim-auto-rp"),(.iosxr,"pim-auto-rp"):
            return 496
        case (.asa,"radius"):
            return 1645
        case (.asa,"radius-acct"):
            return 1646
        case (_,"rip"):
            return 520
        case (.asa,"secureid-udp"):
            return 5510
        case (_,"snmp"):
            return 161
        case (_,"snmptrap"):
            return 162
        case (_,"sunrpc"):
            return 111
        case (_,"syslog"):
            return 514
        case (.asa,"tacacs"),(.nxos,"tacacs"),(.iosxr,"tacacs"):
            return 49
        case (.ios,"tacacs-ds"),(.iosxr,"tacacs-ds"):
            return 49
        case (_,"talk"):
            return 517
        case (_,"tftp"):
            return 69
        case (_,"time"):
            return 37
        case (.asa,"wccp"):
            return 2048
        case (_,"who"):
            return 513
        case (_,"xdmcp"):
            return 177
        default:
            return nil
        }
    }
    //case "ahp","esp","hbh","icmp","ipv6","pcp","sctp","tcp","udp":

    func ipProtocol(deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) -> UInt? {
        switch (deviceType, self) {
        case (.iosxr,"ahp"),(.iosv6,"ahp"),(.nxos,"ahp"),(.nxosv6,"ahp"):
            return 51
        case (.asa,"ah"):
            return 51
        case (.ios,"eigrp"),(.iosv6,"eigrp"),(.asa,"eigrp"),(.nxos,"eigrp"),(.iosxr,"eigrp"):
            return 88
        case (.asa,"esp"),(.iosxr,"esp"),(.iosv6,"esp"),(.nxos,"esp"),(.nxosv6,"esp"):
            return 50
        case (.ios,"esp"):
            delegate?.report(severity: .warning, message: "esp port label is only supported on some ios platforms", delegateWindow: delegateWindow)
            return 50
        case (.iosv6,"hbh"):
            delegate?.report(severity: .error, message: "hop by hop protocol not supported by ACL analyzer, line with protocol hbh will not be included in analysis", delegateWindow: delegateWindow)
            return nil
        case (.ios,"gre"),(.iosv6,"gre"),(.asa,"gre"),(.nxos,"gre"),(.iosxr,"gre"):
            return 47
        case (_,"icmp"):
            return 1
        case (.asa,"icmp6"):
            return 58
        case (.ios,"igmp"),(.iosv6,"igmp"),(.asa,"igmp"),(.nxos,"igmp"),(.iosxr,"igmp"):  //TODO NXOSv6 not supported
            return 2
        case (.iosxr,"igrp"):
            return 9
        case (.iosv6,"ip"),(.nxosv6,"ip"):
            delegate?.report(severity: .error, message: "Found protocol ip in ipv6 ACL, requires correction.  CRITICAL LINE NOT INCLUDED IN ANALYSIS", delegateWindow: delegateWindow)
            return nil
        case (.ios,"ip"),(.asa,"ip"),(.nxos,"ip"),(.iosxr,"ip"):
            return 0
        case (.iosxr,"ipv4"):
            return 0
        case (.iosv6,"ipv6"),(.nxosv6,"ipv6"):
            return 0
        case (.asa,"ipinip"),(.iosxr,"ipinip"),(.ios,"ipinip"):
            return 94
        case (.asa,"ipsec"):
            return 50
        case (.ios,"nos"),(.iosv6,"nos"),(.asa,"nos"),(.nxos,"nos"),(.iosxr,"nos"): // not a typo both ipinip and nos report 94
            return 94
        case (.ios,"ospf"),(.iosv6,"ospf"),(.asa,"ospf"),(.nxos,"ospf"),(.iosxr,"ospf"):  //TODO NXOSv6 not supported
            return 89
        case (.asa,"pcp"),(.iosxr,"pcp"),(.nxos,"pcp"),(.nxosv6,"pcp"):
            return 108
        case (.ios,"pim"),(.iosv6,"pim"),(.asa,"pim"),(.nxos,"pim"),(.iosxr,"pim"):  //TODO NXOSv6 not supported
            return 103
        case (.asa,"pptp"):
            return 47
        case (.nxosv6,"sctp"):
            return 132
        case (.asa,"snp"):
            return 109
        case (_,"tcp"):
            return 6
        case (_,"udp"):
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
