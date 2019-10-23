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
        case (.arista,"acap"),(.aristav6,"acap"):
            return 674
        case (.arista,"acr-nema"),(.aristav6,"acr-nema"):
            return 104
        case (.arista,"afpovertcp"),(.aristav6,"afpovertcp"):
            return 548
        case (.arista,"arns"),(.aristav6,"arns"):
            return 384
        case (.arista,"asip-webadmin"),(.aristav6,"asip-webadmin"):
            return 311
        case (.arista,"at-rtmp"),(.aristav6,"at-rtmp"):
            return 201
        case (.arista,"aurp"),(.aristav6,"aurp"):
            return 387
        case (.arista,"bftp"),(.aristav6,"bftp"):
            return 152
        case (.arista,"bgmp"),(.aristav6,"bgmp"):
            return 264
        case (.arista,"bgp"),(.aristav6,"bgp"):
            return 179
        case (.arista,"chargen"),(.aristav6,"chargen"):
            return 19
        case (.arista,"cisco-tdp"),(.aristav6,"cisco-tdp"):
            return 711
        case (.arista,"citadel"),(.aristav6,"citadel"):
            return 504
        case (.arista,"clearcase"),(.aristav6,"clearcase"):
            return 371
        case (.arista,"cmd"),(.aristav6,"cmd"):
            return 514
        case (.arista,"commerce"),(.aristav6,"commerce"):
            return 542
        case (.arista,"courier"),(.aristav6,"courier"):
            return 530
        case (.arista,"csnet-ns"),(.aristav6,"csnet-ns"):
            return 105
        case (.arista,"cvx"),(.aristav6,"cvx"):
            return 50003
        case (.arista,"cvx-cluster"),(.aristav6,"cvx-cluster"):
            return 50004
        case (.arista,"daytime"),(.aristav6,"daytime"):
            return 13
        case (.arista,"dhcp-failover2"),(.aristav6,"dhcp-failover2"):
            return 847
        case (.arista,"dhcpv6-client"),(.aristav6,"dhcpv6-client"):
            return 546
        case (.arista,"dhcpv6-server"),(.aristav6,"dhcpv6-server"):
            return 547
        case (.arista,"discard"),(.aristav6,"discard"):
            return 9
        case (.arista,"domain"),(.aristav6,"domain"):
            return 53
        case (.arista,"dsp"),(.aristav6,"dsp"):
            return 33
        case (.arista,"echo"),(.aristav6,"echo"):
            return 7
        case (.arista,"efs"),(.aristav6,"efs"):
            return 520
        case (.arista,"epp"),(.aristav6,"epp"):
            return 700
        case (.arista,"esro-gen"),(.aristav6,"esro-gen"):
            return 259
        case (.arista,"exec"),(.aristav6,"exec"):
            return 512
        case (.arista,"finger"),(.aristav6,"finger"):
            return 79
        case (.arista,"ftp"),(.aristav6,"ftp"):
            return 21
        case (.arista,"ftp-data"),(.aristav6,"ftp-data"):
            return 20
        case (.arista,"ftps"),(.aristav6,"ftps"):
            return 990
        case (.arista,"ftps-data"),(.aristav6,"ftps-data"):
            return 989
        case (.arista,"godi"),(.aristav6,"godi"):
            return 848
        case (.arista,"gopher"),(.aristav6,"gopher"):
            return 70
        case (.arista,"gre"),(.aristav6,"gre"):
            return 47
        case (.arista,"ha-cluster"),(.aristav6,"ha-cluster"):
            return 694
        case (.arista,"hostname"),(.aristav6,"hostname"):
            return 101
        case (.arista,"hp-alarm-mgr"),(.aristav6,"hp-alarm-mgr"):
            return 383
        case (.arista,"http-alt"),(.aristav6,"http-alt"):
            return 591
        case (.arista,"http-mgmt"),(.aristav6,"http-mgmt"):
            return 280
        case (.arista,"http-rpc-epmap"),(.aristav6,"http-rpc-epmap"):
            return 593
        case (.arista,"https"),(.aristav6,"https"):
            return 443
        case (.arista,"ident"),(.aristav6,"ident"):
            return 113
        case (.arista,"ieee-mms-ssl"),(.aristav6,"ieee-mms-ssl"):
            return 695
        case (.arista,"imap"),(.aristav6,"imap"):
            return 143
        case (.arista,"imap3"),(.aristav6,"imap3"):
            return 220
        case (.arista,"imaps"),(.aristav6,"imaps"):
            return 993
        case (.arista,"ipp"),(.aristav6,"ipp"):
            return 631
        case (.arista,"ipx"),(.aristav6,"ipx"):
            return 213
        case (.arista,"irc"),(.aristav6,"irc"):
            return 194
        case (.arista,"iris-beep"),(.aristav6,"iris-beep"):
            return 702
        case (.arista,"iscsi"),(.aristav6,"iscsi"):
            return 860
        case (.arista,"isi-gl"),(.aristav6,"isi-gl"):
            return 55
        case (.arista,"iso-tsap"),(.aristav6,"iso-tsap"):
            return 102
        case (.arista,"kerberos"),(.aristav6,"kerberos"):
            return 88
        case (.arista,"kerberos-adm"),(.aristav6,"kerberos-adm"):
            return 749
        case (.arista,"klogin"),(.aristav6,"klogin"):
            return 543
        case (.arista,"kpasswd"),(.aristav6,"kpasswd"):
            return 464
        case (.arista,"kshell"),(.aristav6,"kshell"):
            return 544
        case (.arista,"la-maint"),(.aristav6,"la-maint"):
            return 51
        case (.arista,"lanz"),(.aristav6,"lanz"):
            return 50001
        case (.arista,"ldap"),(.aristav6,"ldap"):
            return 389
        case (.arista,"ldaps"),(.aristav6,"ldaps"):
            return 636
        case (.arista,"ldp"),(.aristav6,"ldp"):
            return 646
        case (.arista,"lmp"),(.aristav6,"lmp"):
            return 701
        case (.arista,"login"),(.aristav6,"login"):
            return 513
        case (.arista,"lpd"),(.aristav6,"lpd"):
            return 515
        case (.arista,"mac-srvr-admin"),(.aristav6,"mac-srvr-admin"):
            return 660
        case (.arista,"matip-type-a"),(.aristav6,"matip-type-a"):
            return 350
        case (.arista,"matip-type-b"),(.aristav6,"matip-type-b"):
            return 351
        case (.arista,"microsoft-ds"),(.aristav6,"microsoft-ds"):
            return 445
        case (.arista,"mlag"),(.aristav6,"mlag"):
            return 4432
        case (.arista,"mlag-arp-sync"),(.aristav6,"mlag-arp-sync"):
            return 50002
        case (.arista,"mpp"),(.aristav6,"mpp"):
            return 218
        case (.arista,"ms-sql-m"),(.aristav6,"ms-sql-m"):
            return 1434
        case (.arista,"ms-sql-s"),(.aristav6,"ms-sql-s"):
            return 1433
        case (.arista,"msdp"),(.aristav6,"msdp"):
            return 639
        case (.arista,"msexch-routing"),(.aristav6,"msexch-routing"):
            return 691
        case (.arista,"msg-icp"),(.aristav6,"msg-icp"):
            return 29
        case (.arista,"msp"),(.aristav6,"msp"):
            return 18
        case (.arista,"nas"),(.aristav6,"nas"):
            return 991
        case (.arista,"nat"),(.aristav6,"nat"):
            return 4532
        case (.arista,"ncp"),(.aristav6,"ncp"):
            return 524
        case (.arista,"netconf-ssh"),(.aristav6,"netconf-ssh"):
            return 830
        case (.arista,"netrjs-1"),(.aristav6,"netrjs-1"):
            return 71
        case (.arista,"netrjs-2"),(.aristav6,"netrjs-2"):
            return 72
        case (.arista,"netrjs-3"),(.aristav6,"netrjs-3"):
            return 73
        case (.arista,"netrjs-4"),(.aristav6,"netrjs-4"):
            return 74
        case (.arista,"netwnews"),(.aristav6,"netwnews"):
            return 532
        case (.arista,"new-rwho"),(.aristav6,"new-rwho"):
            return 550
        case (.arista,"nfs"),(.aristav6,"nfs"):
            return 2049
        case (.arista,"nntp"),(.aristav6,"nntp"):
            return 119
        case (.arista,"nntps"),(.aristav6,"nntps"):
            return 563
        case (.arista,"nsw-fe"),(.aristav6,"nsw-fe"):
            return 27
        case (.arista,"odmr"),(.aristav6,"odmr"):
            return 366
        case (.arista,"openvpn"),(.aristav6,"openvpn"):
            return 1194
        case (.arista,"pim-auto-rp"),(.aristav6,"pim-auto-rp"):
            return 496
        case (.arista,"pkix-timestamp"),(.aristav6,"pkix-timestamp"):
            return 318
        case (.arista,"pkt-krb-ipsec"),(.aristav6,"pkt-krb-ipsec"):
            return 1293
        case (.arista,"pop2"),(.aristav6,"pop2"):
            return 109
        case (.arista,"pop3"),(.aristav6,"pop3"):
            return 110
        case (.arista,"pop3s"),(.aristav6,"pop3s"):
            return 995
        case (.arista,"pptp"),(.aristav6,"pptp"):
            return 1723
        case (.arista,"print-srv"),(.aristav6,"print-srv"):
            return 170
        case (.arista,"ptp-event"),(.aristav6,"ptp-event"):
            return 319
        case (.arista,"ptp-general"),(.aristav6,"ptp-general"):
            return 320
        case (.arista,"qmtp"),(.aristav6,"qmtp"):
            return 209
        case (.arista,"qotd"),(.aristav6,"qotd"):
            return 17
        case (.arista,"radius"),(.aristav6,"radius"):
            return 1812
        case (.arista,"radius-acct"),(.aristav6,"radius-acct"):
            return 1813
        case (.arista,"re-mail-ck"),(.aristav6,"re-mail-ck"):
            return 50
        case (.arista,"remotefs"),(.aristav6,"remotefs"):
            return 556
        case (.arista,"repcmd"),(.aristav6,"repcmd"):
            return 641
        case (.arista,"rje"),(.aristav6,"rje"):
            return 5
        case (.arista,"rlp"),(.aristav6,"rlp"):
            return 39
        case (.arista,"rlzdbase"),(.aristav6,"rlzdbase"):
            return 635
        case (.arista,"rmc"),(.aristav6,"rmc"):
            return 657
        case (.arista,"rpc2portmap"),(.aristav6,"rpc2portmap"):
            return 369
        case (.arista,"rsync"),(.aristav6,"rsync"):
            return 873
        case (.arista,"rtelnet"),(.aristav6,"rtelnet"):
            return 107
        case (.arista,"rtsp"),(.aristav6,"rtsp"):
            return 554
        case (.arista,"sgmp"),(.aristav6,"sgmp"):
            return 153
        case (.arista,"silc"),(.aristav6,"silc"):
            return 706
        case (.arista,"smtp"),(.aristav6,"smtp"):
            return 25
        case (.arista,"smux"),(.aristav6,"smux"):
            return 199
        case (.arista,"snagas"),(.aristav6,"snagas"):
            return 108
        case (.arista,"snmp"),(.aristav6,"snmp"):
            return 161
        case (.arista,"snmptrap"),(.aristav6,"snmptrap"):
            return 162
        case (.arista,"snpp"),(.aristav6,"snpp"):
            return 444
        case (.arista,"sqlserv"),(.aristav6,"sqlserv"):
            return 118
        case (.arista,"sqlsrv"),(.aristav6,"sqlsrv"):
            return 156
        case (.arista,"ssh"),(.aristav6,"ssh"):
            return 22
        case (.arista,"submission"),(.aristav6,"submission"):
            return 587
        case (.arista,"sunrpc"),(.aristav6,"sunrpc"):
            return 111
        case (.arista,"svrloc"),(.aristav6,"svrloc"):
            return 427
        case (.arista,"systat"),(.aristav6,"systat"):
            return 11
        case (.arista,"tacacs"),(.aristav6,"tacacs"):
            return 49
        case (.arista,"talk"),(.aristav6,"talk"):
            return 517
        case (.arista,"tbrpf"),(.aristav6,"tbrpf"):
            return 712
        case (.arista,"tcpmux"),(.aristav6,"tcpmux"):
            return 1
        case (.arista,"tcpnethaspsrv"),(.aristav6,"tcpnethaspsrv"):
            return 475
        case (.arista,"telnet"),(.aristav6,"telnet"):
            return 23
        case (.arista,"time"),(.aristav6,"time"):
            return 37
        case (.arista,"tunnel"),(.aristav6,"tunnel"):
            return 604
        case (.arista,"ups"),(.aristav6,"ups"):
            return 401
        case (.arista,"uucp"),(.aristav6,"uucp"):
            return 540
        case (.arista,"uucp-path"),(.aristav6,"uucp-path"):
            return 117
        case (.arista,"vmnet"),(.aristav6,"vmnet"):
            return 175
        case (.arista,"whois"),(.aristav6,"whois"):
            return 43
        case (.arista,"www"),(.aristav6,"www"):
            return 80
        case (.arista,"xns-ch"),(.aristav6,"xns-ch"):
            return 54
        case (.arista,"xns-mail"),(.aristav6,"xns-mail"):
            return 58
        case (.arista,"xns-time"),(.aristav6,"xns-time"):
            return 52
        case (.arista,"z39-50"),(.aristav6,"z39-50"):
            return 210
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
        case (.arista,"acr-nema"),(.aristav6,"acr-nema"):
            return 104
        case (.arista,"arns"),(.aristav6,"arns"):
            return 384
        case (.arista,"asf-rmcp"),(.aristav6,"asf-rmcp"):
            return 623
        case (.arista,"at-rtmp"),(.aristav6,"at-rtmp"):
            return 201
        case (.arista,"aurp"),(.aristav6,"aurp"):
            return 387
        case (.arista,"auth"),(.aristav6,"auth"):
            return 113
        case (.arista,"bfd"),(.aristav6,"bfd"):
            return 3784
        case (.arista,"bfd-echo"),(.aristav6,"bfd-echo"):
            return 3785
        case (.arista,"bftp"),(.aristav6,"bftp"):
            return 152
        case (.arista,"bgmp"),(.aristav6,"bgmp"):
            return 264
        case (.arista,"biff"),(.aristav6,"biff"):
            return 512
        case (.arista,"bootpc"),(.aristav6,"bootpc"):
            return 68
        case (.arista,"bootps"),(.aristav6,"bootps"):
            return 67
        case (.arista,"chargen"),(.aristav6,"chargen"):
            return 19
        case (.arista,"citadel"),(.aristav6,"citadel"):
            return 504
        case (.arista,"clearcase"),(.aristav6,"clearcase"):
            return 371
        case (.arista,"commerce"),(.aristav6,"commerce"):
            return 542
        case (.arista,"courier"),(.aristav6,"courier"):
            return 530
        case (.arista,"csnet-ns"),(.aristav6,"csnet-ns"):
            return 105
        case (.arista,"daytime"),(.aristav6,"daytime"):
            return 13
        case (.arista,"dhcpv6-client"),(.aristav6,"dhcpv6-client"):
            return 546
        case (.arista,"dhcpv6-server"),(.aristav6,"dhcpv6-server"):
            return 547
        case (.arista,"discard"),(.aristav6,"discard"):
            return 9
        case (.arista,"dnsix"),(.aristav6,"dnsix"):
            return 195
        case (.arista,"domain"),(.aristav6,"domain"):
            return 53
        case (.arista,"dsp"),(.aristav6,"dsp"):
            return 33
        case (.arista,"echo"),(.aristav6,"echo"):
            return 7
        case (.arista,"esro-gen"),(.aristav6,"esro-gen"):
            return 259
        case (.arista,"ftps"),(.aristav6,"ftps"):
            return 990
        case (.arista,"ftps-data"),(.aristav6,"ftps-data"):
            return 989
        case (.arista,"godi"),(.aristav6,"godi"):
            return 848
        case (.arista,"gtp-c"),(.aristav6,"gtp-c"):
            return 2123
        case (.arista,"gtp-prime"),(.aristav6,"gtp-prime"):
            return 3386
        case (.arista,"gtp-u"),(.aristav6,"gtp-u"):
            return 2152
        case (.arista,"ha-cluster"),(.aristav6,"ha-cluster"):
            return 694
        case (.arista,"hp-alarm-mgr"),(.aristav6,"hp-alarm-mgr"):
            return 383
        case (.arista,"http-mgmt"),(.aristav6,"http-mgmt"):
            return 280
        case (.arista,"http-rpc-epmap"),(.aristav6,"http-rpc-epmap"):
            return 593
        case (.arista,"imap3"),(.aristav6,"imap3"):
            return 220
        case (.arista,"ipp"),(.aristav6,"ipp"):
            return 631
        case (.arista,"ipx"),(.aristav6,"ipx"):
            return 213
        case (.arista,"isakmp"),(.aristav6,"isakmp"):
            return 500
        case (.arista,"isi-gl"),(.aristav6,"isi-gl"):
            return 55
        case (.arista,"kerberos"),(.aristav6,"kerberos"):
            return 88
        case (.arista,"kerberos-adm"),(.aristav6,"kerberos-adm"):
            return 749
        case (.arista,"kpasswd"),(.aristav6,"kpasswd"):
            return 464
        case (.arista,"l2tp"),(.aristav6,"l2tp"):
            return 1701
        case (.arista,"la-maint"),(.aristav6,"la-maint"):
            return 51
        case (.arista,"ldap"),(.aristav6,"ldap"):
            return 389
        case (.arista,"ldaps"),(.aristav6,"ldaps"):
            return 636
        case (.arista,"ldp"),(.aristav6,"ldp"):
            return 646
        case (.arista,"lsp-ping"),(.aristav6,"lsp-ping"):
            return 3503
        case (.arista,"matip-type-a"),(.aristav6,"matip-type-a"):
            return 350
        case (.arista,"matip-type-b"),(.aristav6,"matip-type-b"):
            return 351
        case (.arista,"micro-bfd"),(.aristav6,"micro-bfd"):
            return 6784
        case (.arista,"mlag"),(.aristav6,"mlag"):
            return 4432
        case (.arista,"mobile-ip"),(.aristav6,"mobile-ip"):
            return 434
        case (.arista,"monitor"),(.aristav6,"monitor"):
            return 561
        case (.arista,"mpp"),(.aristav6,"mpp"):
            return 218
        case (.arista,"ms-sql-m"),(.aristav6,"ms-sql-m"):
            return 1434
        case (.arista,"msdp"),(.aristav6,"msdp"):
            return 639
        case (.arista,"msg-icp"),(.aristav6,"msg-icp"):
            return 29
        case (.arista,"msp"),(.aristav6,"msp"):
            return 18
        case (.arista,"multihop-bfd"),(.aristav6,"multihop-bfd"):
            return 4784
        case (.arista,"nameserver"),(.aristav6,"nameserver"):
            return 42
        case (.arista,"nas"),(.aristav6,"nas"):
            return 991
        case (.arista,"nat"),(.aristav6,"nat"):
            return 4532
        case (.arista,"ncp"),(.aristav6,"ncp"):
            return 524
        case (.arista,"netbios-dgm"),(.aristav6,"netbios-dgm"):
            return 138
        case (.arista,"netbios-ns"),(.aristav6,"netbios-ns"):
            return 137
        case (.arista,"netbios-ss"),(.aristav6,"netbios-ss"):
            return 139
        case (.arista,"netwall"),(.aristav6,"netwall"):
            return 533
        case (.arista,"new-rwho"),(.aristav6,"new-rwho"):
            return 550
        case (.arista,"nfs"),(.aristav6,"nfs"):
            return 2049
        case (.arista,"nntps"),(.aristav6,"nntps"):
            return 563
        case (.arista,"non500-isakmp"),(.aristav6,"non500-isakmp"):
            return 4500
        case (.arista,"nsw-fe"),(.aristav6,"nsw-fe"):
            return 27
        case (.arista,"ntp"),(.aristav6,"ntp"):
            return 123
        case (.arista,"odmr"),(.aristav6,"odmr"):
            return 366
        case (.arista,"olsr"),(.aristav6,"olsr"):
            return 698
        case (.arista,"openvpn"),(.aristav6,"openvpn"):
            return 1194
        case (.arista,"pim-auto-rp"),(.aristav6,"pim-auto-rp"):
            return 496
        case (.arista,"pkix-timestamp"),(.aristav6,"pkix-timestamp"):
            return 318
        case (.arista,"pkt-krb-ipsec"),(.aristav6,"pkt-krb-ipsec"):
            return 1293
        case (.arista,"pptp"),(.aristav6,"pptp"):
            return 1723
        case (.arista,"ptp-event"),(.aristav6,"ptp-event"):
            return 319
        case (.arista,"ptp-general"),(.aristav6,"ptp-general"):
            return 320
        case (.arista,"qmtp"),(.aristav6,"qmtp"):
            return 209
        case (.arista,"qotd"),(.aristav6,"qotd"):
            return 17
        case (.arista,"radius"),(.aristav6,"radius"):
            return 1812
        case (.arista,"radius-acct"),(.aristav6,"radius-acct"):
            return 1813
        case (.arista,"re-mail-ck"),(.aristav6,"re-mail-ck"):
            return 50
        case (.arista,"repcmd"),(.aristav6,"repcmd"):
            return 641
        case (.arista,"rip"),(.aristav6,"rip"):
            return 520
        case (.arista,"rje"),(.aristav6,"rje"):
            return 5
        case (.arista,"rlp"),(.aristav6,"rlp"):
            return 39
        case (.arista,"rlzdbase"),(.aristav6,"rlzdbase"):
            return 635
        case (.arista,"rmc"),(.aristav6,"rmc"):
            return 657
        case (.arista,"rmonitor"),(.aristav6,"rmonitor"):
            return 560
        case (.arista,"rpc2portmap"),(.aristav6,"rpc2portmap"):
            return 369
        case (.arista,"rtsp"),(.aristav6,"rtsp"):
            return 554
        case (.arista,"sgmp"),(.aristav6,"sgmp"):
            return 153
        case (.arista,"smux"),(.aristav6,"smux"):
            return 199
        case (.arista,"snagas"),(.aristav6,"snagas"):
            return 108
        case (.arista,"snmp"),(.aristav6,"snmp"):
            return 161
        case (.arista,"snmptrap"),(.aristav6,"snmptrap"):
            return 162
        case (.arista,"snpp"),(.aristav6,"snpp"):
            return 444
        case (.arista,"sqlserv"),(.aristav6,"sqlserv"):
            return 118
        case (.arista,"sqlsrv"),(.aristav6,"sqlsrv"):
            return 156
        case (.arista,"sunrpc"),(.aristav6,"sunrpc"):
            return 111
        case (.arista,"svrloc"),(.aristav6,"svrloc"):
            return 427
        case (.arista,"syslog"),(.aristav6,"syslog"):
            return 514
        case (.arista,"systat"),(.aristav6,"systat"):
            return 11
        case (.arista,"tacacs"),(.aristav6,"tacacs"):
            return 49
        case (.arista,"talk"),(.aristav6,"talk"):
            return 517
        case (.arista,"tcpmux"),(.aristav6,"tcpmux"):
            return 1
        case (.arista,"tcpnethaspsrv"),(.aristav6,"tcpnethaspsrv"):
            return 475
        case (.arista,"tftp"),(.aristav6,"tftp"):
            return 69
        case (.arista,"time"),(.aristav6,"time"):
            return 37
        case (.arista,"timed"),(.aristav6,"timed"):
            return 525
        case (.arista,"ups"),(.aristav6,"ups"):
            return 401
        case (.arista,"who"),(.aristav6,"who"):
            return 513
        case (.arista,"xdmcp"),(.aristav6,"xdmcp"):
            return 177
        case (.arista,"xns-ch"),(.aristav6,"xns-ch"):
            return 54
        case (.arista,"xns-mail"),(.aristav6,"xns-mail"):
            return 58
        case (.arista,"xns-time"),(.aristav6,"xns-time"):
            return 52
        case (.arista,"z39-50"),(.aristav6,"z39-50"):
            return 210
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
            case .asa, .nxos, .nxosv6, .arista, .iosxr,.iosxrv6:
                break
            case .ios,.iosv6,.aristav6:
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
        case (.arista,"ahp"),(.iosxr,"ahp"),(.iosxrv6,"ahp"),(.iosv6,"ahp"),(.nxos,"ahp"),(.nxosv6,"ahp"):
            return 51
        case (.asa,"ah"):
            return 51
        case (.ios,"eigrp"),(.iosv6,"eigrp"),(.asa,"eigrp"),(.nxos,"eigrp"),(.iosxr,"eigrp"):
            return 88
        case (.asa,"esp"),(.iosxr,"esp"),(.iosxrv6,"esp"),(.iosv6,"esp"),(.nxos,"esp"),(.nxosv6,"esp"):
            return 50
        case (.ios,"esp"):
            delegate?.report(severity: .warning, message: "esp port label is only supported on some ios platforms", delegateWindow: delegateWindow)
            return 50
        case (.iosv6,"hbh"):
            delegate?.report(severity: .error, message: "hop by hop protocol not supported by ACL analyzer, line with protocol hbh will not be included in analysis", delegateWindow: delegateWindow)
            return nil
        case (.ios,"gre"),(.iosv6,"gre"),(.asa,"gre"),(.nxos,"gre"),(.iosxr,"gre"),(.iosxrv6,"gre"):
            return 47
        case (.ios,"icmp"),(.iosv6,"icmp"),(.asa,"icmp"),(.nxos,"icmp"),(.nxosv6,"icmp"),(.iosxr,"icmp"),(.iosxrv6,"icmp"),(.arista,"icmp"):
            return 1
        case (.aristav6,"icmpv6"):
            return 1
        case (.asa,"icmp6"):
            return 58
        case (.arista,"igmp"),(.ios,"igmp"),(.iosv6,"igmp"),(.asa,"igmp"),(.nxos,"igmp"),(.iosxr,"igmp"),(.iosxrv6,"igmp"):
            return 2
        case (.iosxr,"igrp"),(.iosxrv6,"igrp"):
            return 9
        case (.iosv6,"ip"),(.nxosv6,"ip"):
            delegate?.report(severity: .error, message: "Found protocol ip in ipv6 ACL, requires correction.  CRITICAL LINE NOT INCLUDED IN ANALYSIS", delegateWindow: delegateWindow)
            return nil
        case (.arista,"ip"),(.ios,"ip"),(.asa,"ip"),(.nxos,"ip"),(.iosxr,"ip"):
            return 0
        case (.iosxr,"ipv4"):
            return 0
        case (.aristav6,"ipv6"),(.iosv6,"ipv6"),(.nxosv6,"ipv6"),(.iosxrv6,"ipv6"):
            return 0
        case (.asa,"ipinip"),(.iosxr,"ipinip"),(.iosxrv6,"ipinip"),(.ios,"ipinip"):
            return 94
        case (.asa,"ipsec"):
            return 50
        case (.ios,"nos"),(.iosv6,"nos"),(.asa,"nos"),(.nxos,"nos"),(.iosxr,"nos"),(.iosxrv6,"nos"): // not a typo both ipinip and nos report 94
            return 94
        case (.arista,"ospf"),(.aristav6,"ospf"),(.ios,"ospf"),(.iosv6,"ospf"),(.asa,"ospf"),(.nxos,"ospf"),(.iosxr,"ospf"),(.iosxrv6,"ospf"):
            return 89
        case (.asa,"pcp"),(.iosxr,"pcp"),(.iosxrv6,"pcp"),(.nxos,"pcp"),(.nxosv6,"pcp"):
            return 108
        case (.arista,"pim"),(.ios,"pim"),(.iosv6,"pim"),(.asa,"pim"),(.nxos,"pim"),(.iosxr,"pim"):  //TODO NXOSv6 not supported
            return 103
        case (.asa,"pptp"):
            return 47
        case (.nxosv6,"sctp"),(.iosxrv6,"sctp"):
            return 132
        case (.asa,"snp"):
            return 109
        case (_,"tcp"):
            return 6
        case (_,"udp"):
            return 17
        case (.arista,"vrrp"):
            return 112
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
