//
//  testAsa.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class TestAsa: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    func testAsaMultiNames() {
        let sample = """
        access-list OUT1 extended permit ip host 209.168.200.3 any
        access-list OUT2 extended permit ip host 209.168.200.4 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.aclNames.count == 2)
    }

    func testAsaObject1() {
        let sample = """
        access-list ACL_IN extended permit ip any any
        access-list ACL_IN extended permit object service-obj-http any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.count == 1)
        XCTAssert(acl.accessControlEntries[0].sourceIp[0].minIp == 0)
    }

    func testAsaRemark1() {
        let sample = """
        access-list OUT remark - this is the inside admin address
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.count == 2)
        XCTAssert(acl.accessControlEntries[0].destIp[0].minIp == 0)
        XCTAssert(acl.accessControlEntries[1].sourceIp[0].maxIp == "209.168.200.4".ipv4address!)
    }
    func testAsaIosReject1() {
        let sample = """
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        access-list OUT remark - this is the inside admin address
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.count == 0)
    }

    func testAsaReject() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    func testAsaPortMatch() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == "209.165.201.29".ipv4address)
        XCTAssert(ace.destPort[0].minPort == 80)
        XCTAssert(ace.destPort[0].maxPort == 80)
    }
    
    func testAsaMultipleSpaces() {
        let line = "access-list  ACL_IN  extended deny  tcp  any  host  209.165.201.29  eq  www"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == "209.165.201.29".ipv4address)
        XCTAssert(ace.destPort[0].minPort == 80)
        XCTAssert(ace.destPort[0].maxPort == 80)
    }

    func testAsaIosReject2() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    func testAsaAce1() {
        let line = "access-list outside_in extended permit ip any host 172.16.1.2"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == 0)
        XCTAssert(ace.sourceIp[0].maxIp == "255.255.255.255".ipv4address)
        guard let destIp = "172.16.1.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == destIp)
    }
    func testAsaIcmp() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace!.ipProtocols.first == 1)
        XCTAssert(ace!.sourceIp[0].minIp == 0)
    }
    func testAsaIosIcmpReject() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    
    func testAsaSlash1() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 128.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "127.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "128.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    func testAsaSlash2() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 192.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "63.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "64.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    func testAsaSlash3() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 224.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "31.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "32.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    func testAsaSlash4() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 240.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "15.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "16.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    func testAsaSlash5() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 248.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "7.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "8.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    func testAsaSlash6() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 252.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "4.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testAsaSlash7() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 254.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "2.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testAsaSlash8() {
        let line1 = "access-list 1 extended permit ip 0.0.0.0 255.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "0.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "1.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testAsaSlash9() {
        let line1 = "access-list 1 extended permit ip 3.0.0.0 255.128.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.127.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testAsaLog1() {
        let line = "access-list bob extended permit tcp 3.0.0.0 255.0.0.0 2.0.0.0 255.128.0.0 range 3 7 log"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace != nil)
        let socket = Socket(ipProtocol: 6, sourceIp: "3.128.0.0".ipv4address!, destinationIp: "2.127.3.3".ipv4address!, sourcePort: 33, destinationPort: 6, established: false)!
        let result = ace?.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    
    func testAsaLog2() {
        let line = "access-list bob extended permit tcp 3.0.0.0 255.0.0.0 2.0.0.0 255.128.0.0 range 3 7 log 3"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace != nil)
        let socket = Socket(ipProtocol: 6, sourceIp: "3.128.0.0".ipv4address!, destinationIp: "2.127.3.3".ipv4address!, sourcePort: 33, destinationPort: 6, established: false)!
        let result = ace?.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    func testAsaName() {
        let sample = """
        names
        name 192.168.68.0 Net-AZ4-SERVERS
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.hostnames.count == 1)
        XCTAssert(acl.hostnames["net-az4-servers"] != nil)
        XCTAssert(acl.hostnames["net-az4-servers"] == "192.168.68.0".ipv4address)
    }

    func testAsaNames() {
        let sample = """
names
name 192.168.68.0 Net-AZ4-SERVERS
name 192.168.168.64 Net-AZ4-NETWORK
name 2.2.2.194 AZ4-vSCP
name 9.9.9.196 SCP-DG-BP
name 192.168.168.80 Net-CorpOne1
name 192.168.168.84 Net-CorpOne2
name 4.4.4.58 Net-info1
name 4.4.4.2 Net-info2
name 192.168.68.100 AZ4-vNS1
name 2.2.2.198 trust03
name 2.2.2.196 trust01
name 2.2.2.197 trust02
name 2.2.2.199 trust04
name 2.2.2.200 trust15
name 2.2.2.201 trust16
name 2.2.2.202 trust17
name 2.2.2.203 trust18
name 2.2.2.204 trust19
name 2.2.2.205 trust20
name 2.2.2.206 trust21
name 2.2.2.207 trust22
name 2.2.2.208 trust23
name 2.2.2.209 trust24
name 2.2.2.210 trust25
name 2.2.2.211 trust26
name 2.2.2.212 trust27
name 2.2.2.213 trust28
name 2.2.2.214 trust29
name 2.2.2.215 trust30
name 2.2.2.216 trust31
name 2.2.2.195 AZ4-vTEST
name 3.3.3.34 CorpOneMD1
name 3.3.3.50 CorpOneMD2
name 192.168.168.82 CorpOneMD-inside1
name 192.168.168.86 CorpOneMD-inside2
name 192.168.68.101 AZ4-vNS2
object network NETWORK_OBJ_192.168.0.8_29
 subnet 192.168.0.8 255.255.255.248
object network NETWORK_OBJ_192.168.0.0_24
 subnet 192.168.0.0 255.255.255.0
object network AZ4-vSCP
 host 2.2.2.194
object-group network SCP-Access
 network-object host SCP-DG-BP
object-group network CorpOne
 network-object Net-CorpOne1 255.255.255.252
 network-object Net-CorpOne2 255.255.255.252
object-group network info
 network-object Net-info1 255.255.255.255
 network-object Net-info2 255.255.255.255
 network-object SCP-DG-BP 255.255.255.255
object-group service info-Common tcp
 port-object eq ssh
 port-object eq telnet
object-group network TI-DNS
 network-object host AZ4-vNS1
 network-object host AZ4-vNS2
object-group network all-trust-hosts
 network-object host AZ4-vTEST
 network-object host trust01
 network-object host trust02
 network-object host trust03
 network-object host trust04
 network-object host trust15
 network-object host trust16
 network-object host trust17
 network-object host trust18
 network-object host trust19
 network-object host trust20
 network-object host trust21
 network-object host trust22
 network-object host trust23
 network-object host trust24
 network-object host trust25
 network-object host trust26
 network-object host trust27
 network-object host trust28
 network-object host trust29
 network-object host trust30
 network-object host trust31
 network-object host AZ4-vSCP
object-group network DMZ-INT-DNSAccess
 network-object host AZ4-vTEST
 group-object all-trust-hosts
object-group network DMZ-WEBAccess
 network-object host AZ4-vTEST
 group-object all-trust-hosts
object-group service web tcp
 port-object eq www
 port-object eq https
object-group network DMZ-BBTestAccess
 network-object host AZ4-vTEST
object-group network trust-hosts
 network-object host AZ4-vTEST
object-group network trust01
 network-object host trust01
object-group network trust02
 network-object host trust02
object-group network trust03
 network-object host trust03
object-group network trust04
 network-object host trust04
object-group network trust15
 network-object host trust15
object-group network trust16
 network-object host trust16
object-group network trust17
 network-object host trust17
object-group network trust18
 network-object host trust18
object-group network trust19
 network-object host trust19
object-group network trust20
 network-object host trust20
object-group network trust21
 network-object host trust21
object-group network trust22
 network-object host trust22
object-group network trust23
 network-object host trust23
object-group network trust24
 network-object host trust24
object-group network trust25
 network-object host trust25
object-group network trust26
 network-object host trust26
object-group network trust27
 network-object host trust27
object-group network trust28
 network-object host trust28
object-group network trust29
 network-object host trust29
object-group network trust30
 network-object host trust30
object-group network trust31
 network-object host trust31
object-group network AZ4-vTEST
 network-object host AZ4-vTEST
object-group service standard-trust-tcp-udp tcp-udp
 port-object range 22 23
 port-object range 9080 9083
 port-object range 9090 9093
 port-object range 12345 12349
 port-object eq www
 port-object eq 443
 port-object eq 8080
 port-object eq 9443
object-group network CorpOne_MD_Servers
 network-object host CorpOneMD1
 network-object host CorpOneMD2
object-group service trust-2-bb-tcp-udp tcp-udp
 port-object eq 8194
 port-object eq 8196
object-group service tinfo-2-bb-tcp-udp tcp-udp
 port-object eq 8194
 port-object eq 8196
 port-object eq 9194
access-list dmz_access_in remark The following line is to allow access to external http/https websites from authorized DMZ hosts
access-list dmz_access_in extended permit tcp object-group DMZ-WEBAccess any4 object-group web
access-list dmz_access_in remark The following 4 lines are to allow ICMP for Ping and Traceroute
access-list dmz_access_in extended permit icmp any4 any4 echo
access-list dmz_access_in extended permit icmp any4 any4 echo-reply
access-list dmz_access_in extended permit icmp any4 any4 time-exceeded
access-list dmz_access_in extended permit icmp any4 any4 traceroute
access-list dmz_access_in remark The following 2 lines are to allow DNS queries from authorized DMZ hosts
access-list dmz_access_in extended permit tcp object-group all-trust-hosts object-group TI-DNS eq domain
access-list dmz_access_in extended permit udp object-group all-trust-hosts object-group TI-DNS eq domain
access-list dmz_access_in remark The following line is to allow access to BB md servers from DMZ hosts
access-list dmz_access_in extended permit tcp object-group all-trust-hosts object-group CorpOne_MD_Servers object-group trust-2-bb-tcp-udp
"""
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        //XCTAssert(acl.objectGroupNetworks.count == 1)
        //XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.accessControlEntries.count == 8)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    
    func testAsaNames2() {
        let sample = """
        names
        name 192.168.68.0 Net-AZ4-SERVERS
        name 192.168.168.64 Net-AZ4-NETWORK
        name 2.2.2.194 AZ4-vSCP
        name 9.9.9.196 SCP-DG-BP
        name 192.168.168.80 Net-CorpOne1
        name 192.168.168.84 Net-CorpOne2
        name 4.4.4.58 Net-info1
        name 4.4.4.2 Net-info2
        name 192.168.68.100 AZ4-vNS1
        name 2.2.2.198 trust03
        name 2.2.2.196 trust01
        name 2.2.2.197 trust02
        name 2.2.2.199 trust04
        name 2.2.2.200 trust15
        name 2.2.2.201 trust16
        name 2.2.2.202 trust17
        name 2.2.2.203 trust18
        name 2.2.2.204 trust19
        name 2.2.2.205 trust20
        name 2.2.2.206 trust21
        name 2.2.2.207 trust22
        name 2.2.2.208 trust23
        name 2.2.2.209 trust24
        name 2.2.2.210 trust25
        name 2.2.2.211 trust26
        name 2.2.2.212 trust27
        name 2.2.2.213 trust28
        name 2.2.2.214 trust29
        name 2.2.2.215 trust30
        name 2.2.2.216 trust31
        name 2.2.2.195 AZ4-vTEST
        name 3.3.3.34 CorpOneMD1
        name 3.3.3.50 CorpOneMD2
        name 192.168.168.82 CorpOneMD-inside1
        name 192.168.168.86 CorpOneMD-inside2
        name 192.168.68.101 AZ4-vNS2
        object network NETWORK_OBJ_192.168.0.8_29
        subnet 192.168.0.8 255.255.255.248
        object network NETWORK_OBJ_192.168.0.0_24
        subnet 192.168.0.0 255.255.255.0
        object network AZ4-vSCP
        host 2.2.2.194
        object-group network SCP-Access
        network-object host SCP-DG-BP
        object-group network CorpOne
        network-object Net-CorpOne1 255.255.255.252
        network-object Net-CorpOne2 255.255.255.252
        object-group network info
        network-object Net-info1 255.255.255.255
        network-object Net-info2 255.255.255.255
        network-object SCP-DG-BP 255.255.255.255
        object-group service info-Common tcp
        port-object eq ssh
        port-object eq telnet
        object-group network TI-DNS
        network-object host AZ4-vNS1
        network-object host AZ4-vNS2
        object-group network all-trust-hosts
        network-object host AZ4-vTEST
        network-object host trust01
        network-object host trust02
        network-object host trust03
        network-object host trust04
        network-object host trust15
        network-object host trust16
        network-object host trust17
        network-object host trust18
        network-object host trust19
        network-object host trust20
        network-object host trust21
        network-object host trust22
        network-object host trust23
        network-object host trust24
        network-object host trust25
        network-object host trust26
        network-object host trust27
        network-object host trust28
        network-object host trust29
        network-object host trust30
        network-object host trust31
        network-object host AZ4-vSCP
        object-group network DMZ-INT-DNSAccess
        network-object host AZ4-vTEST
        group-object all-trust-hosts
        object-group network DMZ-WEBAccess
        network-object host AZ4-vTEST
        group-object all-trust-hosts
        object-group service web tcp
        port-object eq www
        port-object eq https
        object-group network DMZ-BBTestAccess
        network-object host AZ4-vTEST
        object-group network trust-hosts
        network-object host AZ4-vTEST
        object-group network trust01
        network-object host trust01
        object-group network trust02
        network-object host trust02
        object-group network trust03
        network-object host trust03
        object-group network trust04
        network-object host trust04
        object-group network trust15
        network-object host trust15
        object-group network trust16
        network-object host trust16
        object-group network trust17
        network-object host trust17
        object-group network trust18
        network-object host trust18
        object-group network trust19
        network-object host trust19
        object-group network trust20
        network-object host trust20
        object-group network trust21
        network-object host trust21
        object-group network trust22
        network-object host trust22
        object-group network trust23
        network-object host trust23
        object-group network trust24
        network-object host trust24
        object-group network trust25
        network-object host trust25
        object-group network trust26
        network-object host trust26
        object-group network trust27
        network-object host trust27
        object-group network trust28
        network-object host trust28
        object-group network trust29
        network-object host trust29
        object-group network trust30
        network-object host trust30
        object-group network trust31
        network-object host trust31
        object-group network AZ4-vTEST
        network-object host AZ4-vTEST
        object-group service standard-trust-tcp-udp tcp-udp
        port-object range 22 23
        port-object range 9080 9083
        port-object range 9090 9093
        port-object range 12345 12349
        port-object eq www
        port-object eq 443
        port-object eq 8080
        port-object eq 9443
        object-group network CorpOne_MD_Servers
        network-object host CorpOneMD1
        network-object host CorpOneMD2
        object-group service trust-2-bb-tcp-udp tcp-udp
        port-object eq 8194
        port-object eq 8196
        object-group service tinfo-2-bb-tcp-udp tcp-udp
        port-object eq 8194
        port-object eq 8196
        port-object eq 9194
access-list outside_access_in remark The following 1 line is to allow info hosts inside to common md ports
access-list outside_access_in extended permit tcp object-group info object-group CorpOne_MD_Servers object-group tinfo-2-bb-tcp-udp
access-list outside_access_in remark The following 1 line is to allow DG hosts inside to common md ports for testing
access-list outside_access_in extended permit tcp object-group SCP-Access object-group CorpOne_MD_Servers object-group tinfo-2-bb-tcp-udp
access-list outside_access_in remark The following 1 line allow SSH access to the test server from authorized IPs
access-list outside_access_in extended permit tcp object-group info object-group all-trust-hosts object-group standard-trust-tcp-udp
"""
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        //XCTAssert(acl.objectGroupNetworks.count == 1)
        //XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.accessControlEntries.count == 3)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    
    func testAsaPortNe() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 ne www"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace != nil)

        guard let socket = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 44, established: false) else {
            XCTAssert(false)
            return
        }
        let result = ace!.analyze(socket: socket)
        XCTAssert(result == .deny)
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result2 = ace!.analyze(socket: socket2)
        XCTAssert(result2 == .neither)
        
        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 81, established: false) else {
            XCTAssert(false)
            return
        }
        let result3 = ace!.analyze(socket: socket3)
        XCTAssert(result3 == .deny)

    }
    func testIpRange() {
        let ip = "209.165.200.0".ipv4address
        XCTAssert(ip != nil)
        let maskIp = "255.255.255.0".ipv4address
        XCTAssert(maskIp != nil)
        let numHosts = maskIp?.netmaskHosts
        XCTAssert(numHosts != nil)
        let ipRange = IpRange(ip: "209.165.200.0", mask: "255.255.255.0", type: .asa)
        XCTAssert(ipRange != nil)
    }
    
    func testAsaSourceObjectGroup() {
        let sample = """
        object-group network denied
            network-object host 10.1.1.4
            network-object host 10.1.1.78
            network-object host 10.1.1.89
        access-list ACL_IN extended deny tcp object-group denied any eq www
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.accessControlEntries.count == 1)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    func testAsaObjectGroupServiceSource1() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq radius
            port-object eq radius-acct
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services1 any
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupServices.count == 3)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 44, established: false)!
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    
    func testAsaObjectGroupServiceSource2() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq domain
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services2 any
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupServices.count == 3)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 44, established: false)!
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    
    func testPortObjectLdap() {
        let sample = """
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupServices["services3"]!.portRanges.count == 1)
    }
    
    func testAsaObjectGroupServiceDest() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq radius
            port-object eq radius-acct
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services1 any object-group services3
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupServices.count == 3)
        XCTAssert(acl.objectGroupServices["services3"] != nil)
        XCTAssert(acl.getObjectGroupService("services3") != nil)
        let service = acl.getObjectGroupService("services3")
        XCTAssert(service!.portRanges.count == 1)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 389, established: false)!
        XCTAssert(acl.accessControlEntries.count == 1)
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 390, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testObjectGroupNetmask() {
        let sample = """
        object-group network eng
            network-object 2.1.1.0 255.255.255.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupNetworks["eng"]!.ipRanges.count == 1)
    }
    func testAsaAny4() {
        let line = "access-list 101 extended permit tcp any4 host 2.2.2.2 eq 80 log 3 interval 10"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 2, errorDelegate: nil, delegateWindow: nil)!
        let socket1 = Socket(ipProtocol: 6, sourceIp: "3.3.3.3".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 40, destinationPort: 80, established: false)!
        let socket2 = Socket(ipProtocol: 6, sourceIp: "3.3.3.3".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 40, destinationPort: 81, established: false)!
        let result1 = ace.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let result2 = ace.analyze(socket: socket2)
        XCTAssert(result2 == .neither)
        
    }
    func testAsaObjectGroupNetmask() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.1.0 255.255.255.0
        access-list ACL extended permit tcp 3.2.0.0 255.255.0.0 object-group eng object-group services1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "2.1.2.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "2.1.1.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
    }
    
    func testAsaEstablishedError() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.0.0 255.255.128.0
        access-list ACL extended permit tcp object-group eng 3.2.0.0 255.255.0.0 object-group services1 established
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    
    func testAsaDuplicateObjectGroup() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network services1
            network-object host 1.1.1.1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupNetworks.count == 0)
        XCTAssert(acl.objectGroupServices.count == 1)

    }
    
    func testAsaProtocolObject1() {
        let sample = """
        object-group protocol tcp_udp_icmp
            protocol-object tcp
            protocol-object icmp
            protocol-object udp
        access-list 101 extended permit object-group tcp_udp_icmp 1.1.63.0 255.255.192.0 2.2.4.0 255.255.254.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.0.3".ipv4address!, destinationIp: "2.2.4.31".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 1, sourceIp: "1.1.63.3".ipv4address!, destinationIp: "2.2.5.31".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 1, sourceIp: "1.1.64.3".ipv4address!, destinationIp: "2.2.4.31".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
    }
    
    func testAsaProtocolObject() {
        let sample = """
        object-group protocol blork
            protocol-object tcp
            protocol-object 8
            protocol-object udp
            protocol-object icmp
            access-list zoom extended permit object-group blork 10.1.4.0 255.255.252.0 20.1.8.0 255.248.0.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 8, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 8, sourceIp: "10.1.8.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testAsaNestedProtocolObject() {
        let sample = """
        object-group protocol alpha
            protocol-object tcp
            protocol-object 8
        object-group protocol beta
            protocol-object udp
            protocol-object icmp
        object-group protocol nest
            group-object alpha
            group-object beta
        access-list zoom extended permit object-group nest 10.1.4.0 255.255.252.0 20.1.8.0 255.248.0.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 8, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 7, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testsaNestedObjectService1() {
        let sample = """
        object-group service alpha tcp
            port-object eq 1
            port-object range 2 5
        object-group service beta tcp
            port-object eq 7
            port-object range 7 9
        object-group service gamma tcp
            group-object alpha
            group-object beta
        access-list crazy extended permit tcp 10.1.16.0 255.255.240.0 20.1.32.0 255.255.224.0 object-group gamma
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 5, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 6, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testAsaNestedObjectServiceInvalid1() {
        let sample = """
        object-group service alpha tcp
            port-object eq 1
            port-object range 2 5
        object-group service beta udp
            port-object eq 7
            port-object range 7 9
        object-group service gamma tcp
            group-object alpha
            group-object beta
        access-list crazy extended permit tcp 10.1.16.0 255.255.240.0 20.1.32.0 255.255.224.0 object-group gamma
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 5, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 8, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testComplexObject1() {
        let sample = """
        object-group protocol bob
            protocol-object tcp
            protocol-object udp
        object-group service alpha tcp
            port-object eq 1
            port-object eq 2
        object-group service beta tcp-udp
            port-object eq 1
            port-object eq 2
        access-list 101 extended permit object-group bob 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 object-group alpha
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testComplexObject2() {
        let sample = """
        object-group protocol bob
            protocol-object tcp
            protocol-object udp
        object-group service alpha tcp
            port-object eq 1
            port-object eq 2
        object-group service beta tcp-udp
            port-object eq 1
            port-object eq 2
        access-list 101 extended permit object-group bob 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 object-group beta
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
    }

    func testComplexObjectWithMultipleSpaces() {
        let sample = """
        object-group  protocol  bob
            protocol-object tcp
            protocol-object  udp
        object-group  service  alpha  tcp
            port-object eq  1
            port-object  eq 2
        object-group  service  beta  tcp-udp
            port-object eq  1
            port-object  eq 2
        access-list 101 extended  permit object-group bob 1.1.1.0  255.255.255.0 2.2.2.0 255.255.255.0  object-group  beta
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
    }

    
    func testAsaNestedObjectNetwork1() {
        let sample = """
        object-group network eng
            network-object host 10.1.1.5
            network-object host 10.1.1.9
            network-object host 10.1.1.89
        object-group network hr
            network-object host 10.1.2.8
            network-object host 10.1.2.12
            network-object 10.2.128.0 255.255.254.0
        object-group network finance
            network-object host 10.1.4.89
            network-object host 10.1.4.100
        object-group network admin
            group-object eng
            group-object hr
            group-object finance
        access-list ACL_IN extended permit ip object-group admin host 209.165.201.29
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.2.129.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 6, sourceIp: "10.2.130.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
    }
    
    
    func testAsaObjectGroupDestNetmask() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.0.0 255.255.128.0
        access-list ACL extended permit tcp object-group eng 3.2.0.0 255.255.0.0 object-group services1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "2.1.33.3".ipv4address!, destinationIp: "3.2.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }

    
    func testAsaObjectGroupAcl() {
        let sample = """
        object-group network denied
            network-object host 10.1.1.4
            network-object host 10.1.1.78
            network-object host 10.1.1.89
        object-group network web
            network-object host 209.165.201.29
            network-object host 209.165.201.16
            network-object host 209.165.201.78
            network-object 209.165.200.0 255.255.255.0
        access-list ACL_IN extended deny tcp object-group denied object-group web eq www
        access-list ACL_IN extended permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupNetworks.count == 2)
        XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.objectGroupNetworks["web"]!.count == 4)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
        
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.200.36".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "10.1.1.5".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
    }
    
    func testAsaPermitAny() {
        let ace = AccessControlEntry(line: "access-list ACL_IN extended permit ip any any", deviceType: .asa, linenum: 3, errorDelegate: nil, delegateWindow: nil)
        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "10.1.1.5".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = ace?.analyze(socket: socket3)
        XCTAssert(result == .permit)
    }
    
    
    func testAsaObjectGroupAclInvalid() {
        let sample = """
access-list outside_in remark Section 1 - Specific whitelist
access-list outside_in remark Temporary exception - #50662 - 2016-10-20 - KD
access-list outside_in extended permit tcp object-group SPECIAL_DEVICES any eq http
access-list outside_in remark Section 2 - General blacklist
access-list outside_in remark Suspicious Ranges - #11246 - 2015-11-05 - KD
access-list outside_in extended deny ip object-group SuspiciousRanges any
access-list outside_in remark Section 3 - General whitelist
access-list outside_in remark web servers - #24548 - 2016-08-19 - KD
access-list outside_in extended permit tcp object-group any WebServers object-group WebProtocols
access-list outside_in remark Section 4 - Specific rules
access-list outside_in remark mail relay - #10456 - 2015-07-29 - KD
access-list outside_in extended permit tcp object-group MailRelay object-group MailServer object-group MailProtocols
"""
        let acl = AccessList(sourceText: sample, deviceType: .asa, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.count == 0)
    }
    
    func testAsaObjectGroupAceInvalid() {
        let line = "access-list outside_in extended permit tcp object-group MailRelay object-group MailServer object-group MailProtocols"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 9, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }

    func testIosExample1() {
        let sample = """
        access-list 102 permit tcp any 10.88.0.0 0.0.255.255 established
        access-list 102 permit tcp any host 10.88.1.2 eq smtp
        access-list 102 permit tcp any any eq domain
        access-list 102 permit udp any any eq domain
        access-list 102 permit icmp any any echo
        access-list 102 permit icmp any any echo-reply
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 6)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: true)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

        let socket3 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

        let socket4 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .deny)

        let socket5 = Socket(ipProtocol: 17, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 53, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .permit)

        let socket6 = Socket(ipProtocol: 17, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 54, established: false)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .deny)

    }

    func testIosLog() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log UserDefinedValue
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testIosLogInput() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log-input UserDefinedValue
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
