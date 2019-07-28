//
//  TestAristaIPv4.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 7/27/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class TestAristaIPv4: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testArista1() {
        let sample = """
        IP Access List test1
        10 permit ip 10.10.10.0/24 any
        20 permit ip 10.30.10.0/24 host 10.20.10.1
        30 permit ip host 10.40.10.1 host 10.20.10.1 log
        40 deny ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 4)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "10.10.10.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "10.20.10.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "10.40.10.1".ipv4address!, destinationIp: "10.20.10.1".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }

    func testArista2() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit tcp 1.1.1.0/30 2.2.2.0/30 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "3.3.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
        
    func testArista3() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit tcp 1.1.1.0/29 eq 80 2.2.2.0/28 eq 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.7".ipv4address!, destinationIp: "2.2.2.15".ipv4address!, sourcePort: 80, destinationPort: 90, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.7".ipv4address!, destinationIp: "2.2.2.15".ipv4address!, sourcePort: 80, destinationPort: 91, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.7".ipv4address!, destinationIp: "2.2.2.16".ipv4address!, sourcePort: 80, destinationPort: 90, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    func testArista4() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 1.1.1.0/27 gt 80 2.2.2.0/26 lt 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 81, destinationPort: 89, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 81, destinationPort: 90, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 80, destinationPort: 89, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.64".ipv4address!, sourcePort: 81, destinationPort: 89, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.32".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 81, destinationPort: 89, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    func testArista4a() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 1.1.1.0/27 lt 80 2.2.2.0/26 gt 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 79, destinationPort: 91, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 80, destinationPort: 91, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 79, destinationPort: 90, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.32".ipv4address!, destinationIp: "2.2.2.63".ipv4address!, sourcePort: 79, destinationPort: 91, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.31".ipv4address!, destinationIp: "2.2.2.64".ipv4address!, sourcePort: 79, destinationPort: 91, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }


    func testArista5() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 1.1.1.0/25 range 10 20 2.2.2.0/24 range 30 40 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 20, destinationPort: 40, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 9, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 10, destinationPort: 29, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.128".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.1.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.127".ipv4address!, destinationIp: "2.2.2.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }

    func testArista6() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 1.1.2.0/23 eq 10 20 30 40 2.2.4.0/22 eq 30 40 50 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 20, destinationPort: 50, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 9, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.4.0".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.8.0".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 10, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }

    func testArista7() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 1.1.2.0/23 neq 10 20 30 40 2.2.4.0/22 neq 30 40 50 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 11, destinationPort: 31, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 10, destinationPort: 31, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 11, destinationPort: 30, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 41, destinationPort: 51, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1.1.3.255".ipv4address!, destinationIp: "2.2.7.255".ipv4address!, sourcePort: 41, destinationPort: 50, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }

}
