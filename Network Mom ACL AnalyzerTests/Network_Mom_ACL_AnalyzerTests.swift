//
//  Network_Mom_ACL_AnalyzerTests.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class Network_Mom_ACL_AnalyzerTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.2 0.0.0.1", deviceType: .ios, linenum: 1) else {
            XCTAssert(false)
            return
        }
        guard let sourceip = "1.1.1.1".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == sourceip)
    }
    
    func testDontCareHostsThree() {
        let three: UInt = 3 // 0.0.0.3
        let dontCareHosts = three.dontCareHosts
        XCTAssert(dontCareHosts == 4)
    }
    
    func testDontCareHostsZero() {
        let zero: UInt = 0 // 0.0.0.0
        let dontCareHosts = zero.dontCareHosts
        XCTAssert(dontCareHosts == 1)
    }

    func testNetmaskZero() {
        let zero: UInt = 0
        let netmaskHosts = zero.netmaskHosts
        XCTAssert(netmaskHosts == 4294967296)
    }
    
    func testNetmaskThirty() {
        let slashThirty: UInt = 4294967292
        let netmaskHosts = slashThirty.netmaskHosts
        XCTAssert(netmaskHosts == 4)
    }
    
    func testBitBoundarySource() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp 3.7.4.18 0.0.0.3 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 2) else {
            XCTAssert(false)
            return
        }
        guard let sourceip = "3.7.4.16".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == sourceip)
    }

    func testEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2 established", deviceType: .ios, linenum: 4) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == true)
    }
    func testEstablishedMustBeTcp() {
        let ace = AccessControlEntry(line: "permit ip any any established", deviceType: .ios, linenum: 4)
        XCTAssert(ace == nil)
    }
    func testEstablishedCannotBeUdp() {
        let ace = AccessControlEntry(line: "permit udp any any established", deviceType: .ios, linenum: 4)
        XCTAssert(ace == nil)
    }
    func testDummies1() {
        let sample = """
        access-list 101 remark This ACL is to control the outbound router traffic.
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 80
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 443
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "192.168.8.41".ipv4address!, destinationIp: "212.221.4.5".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .permit)
        
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "192.168.3.41".ipv4address!, destinationIp: "212.221.4.5".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testAnalyzeEstablished1() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3) else {
            XCTAssert(false)
            return
        }
        guard let socket = Socket(ipProtocol: 6, sourceIp: 3, destinationIp: 5, sourcePort: 33, destinationPort: 44, established: true) else {
            XCTAssert(false)
            return
        }
        let result = ace.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    func testAnalyzeEstablished2() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3) else {
            XCTAssert(false)
            return
        }
        guard let socket = Socket(ipProtocol: 6, sourceIp: 3, destinationIp: 5, sourcePort: 33, destinationPort: 44, established: false) else {
            XCTAssert(false)
            return
        }
        let result = ace.analyze(socket: socket)
        XCTAssert(result == .neither)
    }

    
    func testNotEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2", deviceType: .ios, linenum: 4) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == false)
    }

    func testBitBoundaryDest() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 3) else {
            XCTAssert(false)
            return
        }
        guard let destip = "2.2.2.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == destip)
    }

    func testInvalidProtocolDestPort() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255 eq 80", deviceType: .ios, linenum: 5)
        XCTAssert(ace == nil)
    }
    
    func testInvalidNetmaskIos() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0", deviceType: .ios, linenum: 5)
        XCTAssert(ace == nil)
    }
    
    func testInvalidProtocolSourcePort() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 eq 80 2.2.2.128 0.0.0.63", deviceType: .ios, linenum: 5)
        XCTAssert(ace == nil)
    }
    
    func testUdpNamedPort() {
        let ace = AccessControlEntry(line: "permit udp 1.1.1.0 0.0.0.255 eq snmp 2.2.2.128 0.0.0.63 eq ntp", deviceType: .ios, linenum: 5)
        XCTAssert(ace?.sourcePort[0].minPort == 161)
        XCTAssert(ace?.destPort[0].maxPort == 123)
    }

    func testTcpNamedPort() {
        let ace = AccessControlEntry(line: "permit tcp 1.1.1.0 0.0.0.255 eq domain 2.2.2.128 0.0.0.63 eq nfs", deviceType: .ios, linenum: 5)
        XCTAssert(ace?.sourcePort[0].maxPort == 53)
        XCTAssert(ace?.destPort[0].minPort == 2049)
    }
    func testIcmpName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-reply", deviceType: .ios, linenum: 6)
        XCTAssert(ace?.ipProtocol == 1)
    }
    func testIcmpNumber() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 14", deviceType: .ios, linenum: 6)
        XCTAssert(ace?.ipProtocol == 1)
        XCTAssert(ace?.icmpMessage?.type == 14)
    }
    func testIcmpInvalidName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-bogus", deviceType: .ios, linenum: 6)
        XCTAssert(ace == nil)
    }
    func testIosXrLine() {
        let line = "permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7)
        XCTAssert(ace?.destPort[0].minPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.sourceIp[0].minIp == sourceip)
    }
    func testIosXrIndented() {
        let line = "  10 permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7)
        XCTAssert(ace?.destPort[0].minPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.sourceIp[0].minIp == sourceip)
    }

    func testIosXrLineNumbered() {
        let line = "10 permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7)
        XCTAssert(ace?.destPort[0].minPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.sourceIp[0].minIp == sourceip)
    }
    
    func testIosXrSequence() {
        let sample = """
ipv4 access-list acl_hw_1
  10 permit icmp 192.168.36.0 0.0.0.255 any
  20 permit ip 172.16.3.0 0.0.255.255 any
  30 deny tcp any any
"""
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 3)
    }
        
    func testIosXr() {
        let sample = """
ipv4 access-list acl_hw_1
   permit icmp 192.168.36.0 0.0.0.255 any
   permit ip 172.16.3.0 0.0.255.255 any
   deny tcp any any
"""
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 3)
    }
    
    
    
    func testIosMultiNames() {
        let sample = """
        access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1
        access-list 101 permit icmp host 10.1.1.1 host 172.16.1.1
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.names.count == 2)
    }

    
    func testIosName() {
        let sample = """
        ip access-list extended blockacl
        deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21
        deny tcp any 172.16.50.0 0.0.0.255 eq 23
        permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 3)
        XCTAssert(acl.names.contains("blockacl"))
        
    }
    func testIos() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        guard let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destPort[0].minPort == 21)
        XCTAssert(ace.ipProtocol == 6)
        XCTAssert(ace.aclAction == .deny)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
