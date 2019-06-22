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
        XCTAssert(ace.minSourceIp == sourceip)
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
        XCTAssert(ace.minSourceIp == sourceip)
    }

    func testEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2 established", deviceType: .ios, linenum: 4) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == true)
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
        XCTAssert(ace.minDestIp == destip)
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
        XCTAssert(ace?.minSourcePort == 161)
        XCTAssert(ace?.maxDestPort == 123)
    }

    func testTcpNamedPort() {
        let ace = AccessControlEntry(line: "permit tcp 1.1.1.0 0.0.0.255 eq domain 2.2.2.128 0.0.0.63 eq nfs", deviceType: .ios, linenum: 5)
        XCTAssert(ace?.maxSourcePort == 53)
        XCTAssert(ace?.minDestPort == 2049)
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
        XCTAssert(ace?.minDestPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.minSourceIp == sourceip)
    }
    func testIosXrIndented() {
        let line = "  10 permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7)
        XCTAssert(ace?.minDestPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.minSourceIp == sourceip)
    }

    func testIosXrLineNumbered() {
        let line = "10 permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7)
        XCTAssert(ace?.minDestPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.minSourceIp == sourceip)
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
    
    
    func testAsaRemark1() {
        let sample = """
        access-list OUT remark - this is the inside admin address
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.count == 2)
        XCTAssert(acl.accessControlEntries[0].minDestIp == 0)
        XCTAssert(acl.accessControlEntries[1].maxSourceIp == "209.168.200.4".ipv4address!)
    }
    func testAsaIosReject1() {
        let sample = """
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        access-list OUT remark - this is the inside admin address
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 0)
    }

    func testAsaObject1() {
        let sample = """
        access-list ACL_IN extended permit ip any any
        access-list ACL_IN extended permit object service-obj-http any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.count == 1)
        XCTAssert(acl.accessControlEntries[0].minSourceIp == 0)
    }
    
    func testAsaPortMatch() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.minDestIp == "209.165.201.29".ipv4address)
        XCTAssert(ace.minDestPort == 80)
        XCTAssert(ace.maxDestPort == 80)
    }
    func testAsaIosReject2() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8)
        XCTAssert(ace == nil)
    }
    func testAsaAce1() {
        let line = "access-list outside_in extended permit ip any host 172.16.1.2"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.minSourceIp == 0)
        XCTAssert(ace.maxSourceIp == "255.255.255.255".ipv4address)
        guard let destIp = "172.16.1.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.minDestIp == destIp)
    }
    func testAsaIcmp() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace!.ipProtocol == 1)
        XCTAssert(ace!.minSourceIp == 0)
    }
    func testAsaIosIcmpReject() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8)
        XCTAssert(ace == nil)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
