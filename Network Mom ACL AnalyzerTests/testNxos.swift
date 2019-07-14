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
            10 permit ip 192.168.2.0/24 any established
            15 permit tcp 192.168.3.0/24 any established
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq www
            30 permit udp 20.20.0.0/14 range domain bootps 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50 log
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
        let socket6 = Socket(ipProtocol: 6, sourceIp: "192.168.3.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: false)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .deny)
        let socket7 = Socket(ipProtocol: 6, sourceIp: "192.168.3.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: true)!
        let result7 = acl.analyze(socket: socket7)
        XCTAssert(result7 == .permit)
        let socket8 = Socket(ipProtocol: 6, sourceIp: "192.168.2.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: true)!
        let result8 = acl.analyze(socket: socket8)
        XCTAssert(result8 == .deny)

    }
    
    func testNxosObjects1() {
        let sample = """
        object-group ip address ipv4-addr-group-13
            host 10.99.32.6
            192.168.7.0/24
            192.168.8.0 0.0.0.255
        object-group ip port NYC-datacenter-ports
            eq 80
            range 30 34
        object-group ip port LA-ports
            neq 77
        object-group ip port TOK-ports
            lt 30
            gt 65500
        ip access-list bob
            15 permit tcp addrgroup ipv4-addr-group-13  10.0.0.0/23 portgroup NYC-datacenter-ports
            17 permit udp 192.168.10.0/24 192.168.11.0/24 portgroup LA-ports
            19 permit tcp 192.168.12.0/24 192.168.13.0/24 portgroup TOK-ports established
        """
        
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupServices.count == 3)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.99.32.6".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "192.168.7.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
        
        let socket4 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 81, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .deny)

        let socket5 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 31, established: false)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .permit)

        let socket6 = Socket(ipProtocol: 17, sourceIp: "192.168.10.33".ipv4address!, destinationIp: "192.168.11.194".ipv4address!, sourcePort: 33, destinationPort: 76, established: false)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .permit)

        let socket7 = Socket(ipProtocol: 17, sourceIp: "192.168.10.33".ipv4address!, destinationIp: "192.168.11.194".ipv4address!, sourcePort: 33, destinationPort: 77, established: false)!
        let result7 = acl.analyze(socket: socket7)
        XCTAssert(result7 == .deny)

        let socket8 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 29, established: true)!
        let result8 = acl.analyze(socket: socket8)
        XCTAssert(result8 == .permit)

        let socket9 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 30, established: true)!
        let result9 = acl.analyze(socket: socket9)
        XCTAssert(result9 == .deny)

        let socket10 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 65501, established: true)!
        let result10 = acl.analyze(socket: socket10)
        XCTAssert(result10 == .permit)

        let socket11 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 65500, established: true)!
        let result11 = acl.analyze(socket: socket11)
        XCTAssert(result11 == .permit)

    }


    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
