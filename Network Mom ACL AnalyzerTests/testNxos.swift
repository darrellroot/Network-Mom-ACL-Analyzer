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

    func testNxos1() {
        let sample = """
        ip access-list bob
            10 permit ip 192.168.2.0/24 any
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            30 permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50 capture session 3
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }

    func testNxos2() {
        let sample = """
        ip access-list bob
            permit ip 192.168.2.0/24 any
            permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50 capture session 3
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
