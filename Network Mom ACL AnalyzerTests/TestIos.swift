//
//  Network_Mom_ACL_AnalyzerTests.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class TestIos: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.2 0.0.0.1", deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp 3.7.4.18 0.0.0.3 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 2, errorDelegate: nil, delegateWindow: nil) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2 established", deviceType: .ios, linenum: 4, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == true)
    }
    func testEstablishedMustBeTcp() {
        let ace = AccessControlEntry(line: "permit ip any any established", deviceType: .ios, linenum: 4, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    func testEstablishedCannotBeUdp() {
        let ace = AccessControlEntry(line: "permit udp any any established", deviceType: .ios, linenum: 4, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    func testCmdForMatt() {
        let line1 = "access-list 101 permit tcp 1.2.3.192 0.0.0.63 eq cmd 10.0.0.0 0.255.255.255"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
    }
    
    func testMultipleSpacesForMatt() {
        let line1 = "access-list 101  permit  tcp  1.2.3.192 0.0.0.63 eq cmd 10.0.0.0 0.255.255.255"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
    }

    func testIosProtocolNumbered1() {
        let line1 = "access-list 101 permit 6 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
    }
    
    func testIosProtocolNumbered2() {
        let line1 = "access-list 101 permit 0 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 == nil)
    }

    func testIosProtocolNumbered3() {
        let line1 = "access-list 101 permit 256 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 == nil)
    }

    func testIosProtocol3() {
        let sample = """
ip access-list 101 extended
permit ip host 10.4.4.2 any
permit ip host 10.0.0.44 any
permit ip host 10.0.0.1 any
permit ip host 10.0.0.2 any
"""
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 3, sourceIp: "10.4.4.2".ipv4address!, destinationIp: "100.1.1.1".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 3, sourceIp: "10.4.4.3".ipv4address!, destinationIp: "100.1.1.1".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }

    func testIosLog() {
        let line1 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 log"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result1 = ace1?.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let line2 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 log-input"
        let ace2 = AccessControlEntry(line: line2, deviceType: .ios, linenum: 2, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace2 != nil)
        let result2 = ace2?.analyze(socket: socket1)
        XCTAssert(result2 == .permit)
        let line3 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 dfwefwef"
        let ace3 = AccessControlEntry(line: line3, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace3 == nil)
        
    }
    func testIosSlash0() {
        let line1 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "147.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .permit)
    }

    func testIosSlash1() {
        let line1 = "access-list 1 permit ip 0.0.0.0 127.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "127.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "128.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash2() {
        let line1 = "access-list 1 permit ip 0.0.0.0 63.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "63.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "64.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash3() {
        let line1 = "access-list 1 permit ip 0.0.0.0 31.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "31.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "32.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash4() {
        let line1 = "access-list 1 permit ip 0.0.0.0 15.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "15.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "16.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash5() {
        let line1 = "access-list 1 permit ip 0.0.0.0 7.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "7.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "8.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash6() {
        let line1 = "access-list 1 permit ip 0.0.0.0 3.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "4.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash7() {
        let line1 = "access-list 1 permit ip 0.0.0.0 1.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "2.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash8() {
        let line1 = "access-list 1 permit ip 0.0.0.0 0.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "0.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "1.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash9() {
        let line1 = "access-list 1 permit ip 3.0.0.0 0.127.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.127.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash10() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.63.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.191.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.192.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash11() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.31.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.159.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.160.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash12() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.15.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.143.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.144.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash13() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.7.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.135.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.136.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash14() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.3.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.131.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.132.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash15() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.1.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.129.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.130.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash16() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.0.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.129.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash17() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.0.127.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.127.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.128.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash18() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.63.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.127.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.128.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash19() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.31.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.95.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.96.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash20() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.15.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.79.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.80.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash21() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.7.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.71.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.72.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash22() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.3.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.67.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.68.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash23() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.1.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.65.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.66.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash24() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.0.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.65.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash25() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.0.127 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.127".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.128".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash26() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.63 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.127".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.128".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash27() {
        let line1 = "access-list 1 permit ip 0.0.0.64 0.0.0.31 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "0.0.0.95".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "0.0.0.96".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash28() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.15 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.79".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.80".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash29() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.7 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.71".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.72".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash30() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.3 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.67".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.68".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash31() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.1 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.65".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.66".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash32() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.64".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.65".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosNe1() {
        let line = "access-list 101 permit tcp host 1.1.1.1 any neq ssh"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 40, established: false)!
        XCTAssert(ace != nil)
        let result1 = ace?.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = ace?.analyze(socket: socket2)
        XCTAssert(result2 == .neither)
    }
    
    func testIosNeInvalid1() {
        let line = "access-list 101 permit tcp host 1.1.1.1 any ne ssh"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }

    func testDummies1() {
        let sample = """
        access-list 101 remark This ACL is to control the outbound router traffic.
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 80
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 443
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3, errorDelegate: nil, delegateWindow: nil) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3, errorDelegate: nil, delegateWindow: nil) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2", deviceType: .ios, linenum: 4, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == false)
    }

    func testBitBoundaryDest() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 3, errorDelegate: nil, delegateWindow: nil) else {
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
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255 eq 80", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    
    func testInvalidNetmaskIos() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    
    func testInvalidProtocolSourcePort() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 eq 80 2.2.2.128 0.0.0.63", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    
    func testUdpNamedPort() {
        let ace = AccessControlEntry(line: "permit udp 1.1.1.0 0.0.0.255 eq snmp 2.2.2.128 0.0.0.63 eq ntp", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.sourcePort[0].minPort == 161)
        XCTAssert(ace?.destPort[0].maxPort == 123)
    }

    func testTcpNamedPort() {
        let ace = AccessControlEntry(line: "permit tcp 1.1.1.0 0.0.0.255 eq domain 2.2.2.128 0.0.0.63 eq nfs", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.sourcePort[0].maxPort == 53)
        XCTAssert(ace?.destPort[0].minPort == 2049)
    }
    func testIcmpName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-reply", deviceType: .ios, linenum: 6, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.ipProtocols.first == 1)
    }
    func testIcmpNumber() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 14", deviceType: .ios, linenum: 6, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.ipProtocols.first == 1)
        XCTAssert(ace?.icmpMessages.first!.type == 14)
    }
    func testIcmpInvalidName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-bogus", deviceType: .ios, linenum: 6, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    func testIosXrLine() {
        let line = "permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.destPort[0].minPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.sourceIp[0].minIp == sourceip)
    }
    
    func testSyslog() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq syslog"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.destPort[0].minPort == 514)
    }
    
    func testIosLog2() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log
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
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log-input
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

    
    func testIsakmp() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq isakmp"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.destPort[0].minPort == 500)
    }

    func testNon500isakmp() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq non500-isakmp"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.destPort[0].minPort == 4500)
    }

    func testEsp() {
    let line = "permit esp 192.168.36.0 0.0.0.255 host 1.1.1.1 "
    let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, errorDelegate: nil, delegateWindow: nil)
    XCTAssert(ace?.ipProtocols.first == 50)
    }


    
    
    
    func testIosMultiNames() {
        let sample = """
        access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1
        access-list 101 permit icmp host 10.1.1.1 host 172.16.1.1
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.aclNames.count == 2)
    }

    func testIosName() {
        let sample = """
        ip access-list extended blockacl
        deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21
        deny tcp any 172.16.50.0 0.0.0.255 eq 23
        permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.count == 3)
        XCTAssert(acl.aclNames.contains("blockacl"))
        
    }
    func testIos() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        guard let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8, errorDelegate: nil, delegateWindow: nil) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destPort[0].minPort == 21)
        XCTAssert(ace.ipProtocols.first == 6)
        XCTAssert(ace.aclAction == .deny)
    }

}
