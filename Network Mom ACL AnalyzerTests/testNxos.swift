//
//  testNxos.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 7/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class testNxos: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCidr1() {
        let ipRange = IpRange(cidr: "131.252.209.0/24")!
        XCTAssert(ipRange.bitAligned == true)
        XCTAssert(ipRange.minIp == "131.252.209.0".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.255".ipv4address)
    }
    func testCidr2() {
        let ipRange = IpRange(cidr: "131.252.209.12/24")!
        XCTAssert(ipRange.bitAligned == false)
        XCTAssert(ipRange.minIp == "131.252.209.0".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.255".ipv4address)
    }
    func testCidr3() {
        let ipRange = IpRange(cidr: "131.252.209.18/31")!
        XCTAssert(ipRange.bitAligned == true)
        XCTAssert(ipRange.minIp == "131.252.209.18".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.19".ipv4address)
    }

    func testNxos1() {
        let sample = """
        ip access-list bob
            10 permit ip 192.168.2.0/24 any
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            30 permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 49, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 50, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
        let socket4 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 15, destinationPort: 50, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)
        let socket5 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 9, destinationPort: 50, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .deny)
    }

    func testNxos2() {
        let sample = """
        ip access-list bob
            permit ip 192.168.2.0/24 any
            permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }
    
    func testNxos3() {
        let sample = """
        ip access-list bob
            10 permit ip 192.168.2.0/24 any
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq www
            30 permit udp 20.20.0.0/14 range domain bootps 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket1a = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 81, established: false)!
        let result1a = acl.analyze(socket: socket1a)
        XCTAssert(result1a == .deny)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 49, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 50, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
        let socket4 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 53, destinationPort: 50, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)
        let socket5 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 52, destinationPort: 50, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .deny)
    }


    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
