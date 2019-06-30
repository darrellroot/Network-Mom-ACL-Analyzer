//
//  testAsa.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class testAsa: XCTestCase {

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
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.names.count == 2)
    }

    func testAsaObject1() {
        let sample = """
        access-list ACL_IN extended permit ip any any
        access-list ACL_IN extended permit object service-obj-http any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
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
        let acl = AccessList(sourceText: sample, deviceType: .asa)
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
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 0)
    }

    func testAsaReject() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace == nil)
    }
    func testAsaPortMatch() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == "209.165.201.29".ipv4address)
        XCTAssert(ace.destPort[0].minPort == 80)
        XCTAssert(ace.destPort[0].maxPort == 80)
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
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace!.ipProtocol == 1)
        XCTAssert(ace!.sourceIp[0].minIp == 0)
    }
    func testAsaIosIcmpReject() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8)
        XCTAssert(ace == nil)
    }
    
    func testAsaPortNe() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 ne www"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
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
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroups.count == 1)
        XCTAssert(acl.objectGroups["denied"]!.count == 3)
        XCTAssert(acl.accessControlEntries.count == 1)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)

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
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroups.count == 2)
        XCTAssert(acl.objectGroups["denied"]!.count == 3)
        XCTAssert(acl.objectGroups["web"]!.count == 4)
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
        let ace = AccessControlEntry(line: "access-list ACL_IN extended permit ip any any", deviceType: .asa, linenum: 3)
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
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.count == 0)
    }
    
    func testAsaObjectGroupAceInvalid() {
        let line = "access-list outside_in extended permit tcp object-group MailRelay object-group MailServer object-group MailProtocols"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 9)
        XCTAssert(ace == nil)
    }



    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
