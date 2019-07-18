//
//  testIosXr.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 7/16/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class testIosXr: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testIosXr1() {
        let sample = """
        ipv4 access-list acl_1
            10 remark Do not allow user1 to telnet out
            20 permit 172.16.0.0 0.0.255.255
            30 permit 192.168.34.0 0.0.0.255
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxr, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "172.16.3.3".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "172.15.3.3".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testIosXr2() {
        let sample = """
ipv4 access-list acl_1
10 permit ip host 10.3.3.3 host 172.16.5.34
20 permit icmp any any
30 permit tcp any host 10.3.3.3
40 permit ip host 10.4.4.4 any
60 permit ip host 172.16.2.2 host 10.3.3.12
70 permit ip host 10.3.3.3 host 1.1.1.1 log
80 permit tcp host 10.3.3.3 host 10.1.2.2
"""

        let acl = AccessList(sourceText: sample, deviceType: .iosxr, delegate: nil, delegateWindow: nil)
        
        XCTAssert(acl.accessControlEntries.count == 7)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.3.3.3".ipv4address!, destinationIp: "172.16.5.34".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.3.3.4".ipv4address!, destinationIp: "172.16.5.34".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "172.16.2.2".ipv4address!, destinationIp: "10.3.3.12".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

        let socket4 = Socket(ipProtocol: 6, sourceIp: "10.3.3.3".ipv4address!, destinationIp: "10.1.2.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)

        let socket5 = Socket(ipProtocol: 17, sourceIp: "10.3.3.3".ipv4address!, destinationIp: "10.1.2.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .deny)
    }
    
    func testIosXr3() {
        let sample = """
object-group network ipv4 real
host 100.1.1.1
ipv4 access-list real
10 permit icmp any any
20 permit tcp any net-group real eq www
30 permit tcp any net-group real eq www log
40 permit tcp any net-group real eq ftp
50 permit tcp any net-group real eq telnet
60 permit tcp any net-group real eq pop3
70 permit tcp any net-group real eq smtp
80 permit tcp any net-group real eq domain
90 permit tcp any net-group real eq ftp-data
100 permit tcp any net-group real established
110 permit tcp any net-group real eq 389
111 permit udp any net-group real eq 389
120 permit tcp any net-group real eq 636
121 permit udp any net-group real eq 636
200 permit ipv4 any any
"""
        let acl = AccessList(sourceText: sample, deviceType: .iosxr, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.3.3.3".ipv4address!, destinationIp: "172.16.5.34".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }

    func testIosXrNestedObjectGroup() {
        let sample = """
object-group network ipv4 real
host 100.1.1.1
object-group network ipv4 acl1
description network-object-group
host 10.20.2.3
10.20.20.3 255.255.255.0
range 10.20.20.10 10.20.20.40
object-group real1
ipv4 access-list acl1
10 permit tcp  net-group  group1  host 10.10.10.1  eq 2200
20 permit tcp 10.10.10.3/32  host 1.1.1.2   eq  2000
"""
        let acl = AccessList(sourceText: sample, deviceType: .iosxr, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.10.10.3".ipv4address!, destinationIp: "1.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 2000, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)

        let socket1r = Socket(ipProtocol: 6, sourceIp: "10.10.10.3".ipv4address!, destinationIp: "1.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 2001, established: false)!
        let result1r = acl.analyze(socket: socket1r)
        XCTAssert(result1r == .deny)

        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.20.2.3".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)

        let socket2r = Socket(ipProtocol: 6, sourceIp: "10.20.2.4".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result2r = acl.analyze(socket: socket2r)
        XCTAssert(result2r == .deny)

        let socket3 = Socket(ipProtocol: 6, sourceIp: "100.1.1.1".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

        let socket3r = Socket(ipProtocol: 6, sourceIp: "100.1.1.2".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result3r = acl.analyze(socket: socket3r)
        XCTAssert(result3r == .deny)

        let socket4 = Socket(ipProtocol: 6, sourceIp: "10.20.20.15".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)

        let socket4r = Socket(ipProtocol: 6, sourceIp: "10.20.20.41".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result4r = acl.analyze(socket: socket4r)
        XCTAssert(result4r == .permit)

        let socket5 = Socket(ipProtocol: 6, sourceIp: "10.20.20.40".ipv4address!, destinationIp: "10.10.10.1".ipv4address!, sourcePort: 33, destinationPort: 2200, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .permit)

    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
