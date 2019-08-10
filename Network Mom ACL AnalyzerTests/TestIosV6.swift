//
//  TestIosV6.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 8/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
import Network

class TestIosV6: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testTcpNamedPort() {
        let ace = AccessControlEntry(line: "permit tcp 2001:db8::/32 eq domain 2001:3:4::4/48 eq www", deviceType: .iosv6, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.sourcePort[0].maxPort == 53)
        XCTAssert(ace?.destPort[0].minPort == 80)
    }
    func testV6() {
        let address = IPv6Address("2001:0db8::3")!
        let oneTwentyEight = UInt128(ipv6: address)
        
        XCTAssert(oneTwentyEight.ipv6 == "2001:0db8:0000:0000:0000:0000:0000:0003")
    }
    func testIpRangeV6() {
        let ipRange = IpRange(cidr: "2001:0db8::3/32")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == false)
        debugPrint(ipRange)
    }
    func testIpRangeV6d() {
        let ipRange = IpRange(cidr: "2001:0db8::/32")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == true)
        debugPrint(ipRange)
    }

    func testIpRangeV6a() {
        let ipRange = IpRange(cidr: "::1/127")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == false)
        //debugPrint(ipRange)
    }
    func testIpRangeV6b() {
        let ipRange = IpRange(cidr: "::2/127")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == true)
        //debugPrint(ipRange)
    }
    func testIosV61() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp any any eq www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2602:0db8::3".ipv6address!, destinationIp: "2602:0db8::3".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2602:0db8::3".ipv6address!, destinationIp: "2602:0db8::3".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV62() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 2001:DB8::/32 any eq www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2001:0db8::3".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db9::3".ipv6address!, destinationIp: "2001:0db8::3".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV63() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 2001:DB8::/32 2620:0db8:0123:4567:89ab:cdef:0123:4567/127 eq www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4568".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4566".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4565".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4566".ipv6address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4566".ipv6address!, sourcePort: 33, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV64() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 2001:DB8::/32 range 10 20 2620:0db8:0123:4567:89ab:cdef:0123:4567/127 gt www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 9, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 20, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 21, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV65() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 2001:DB8::/32 range 10 20 10.10.10.0/24 gt www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV66() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 1.1.1.0/24 range 10 20 10.10.10.0/24 gt www
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    //testing ipv6 acl in ipv4 initializer, should fail
    func testIosV67() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp 2001:DB8::/32 range 10 20 2620:0db8:0123:4567:89ab:cdef:0123:4567/127 gt www
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8::3".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV68() {
        let sample = """
    ipv6 access-list extended acl1
    permit ipv6 host 2001:DB8:0:4::2 any
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    
    // protocol ip not valid in ipv6 acl
    func testIosV69() {
        let sample = """
    ipv6 access-list extended acl1
    permit ip host 2001:DB8:0:4::2 any
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV610() {
        let sample = """
    ipv6 access-list extended acl1
    permit ipv6 host 2001:DB8:0:4::2 host 2620:0db8:0123:4567:89ab:cdef:0123:4567
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4568".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    //invalid port with protocol ipv6
    func testIosV611() {
        let sample = """
    ipv6 access-list extended acl1
    permit ipv6 host 2001:DB8:0:4::2 host 2620:0db8:0123:4567:89ab:cdef:0123:4567 eq 80
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    //invalid port with protocol ipv6
    func testIosV612() {
        let sample = """
    ipv6 access-list extended acl1
    permit 12 host 2001:DB8:0:4::2 neq 33 host 2620:0db8:0123:4567:89ab:cdef:0123:4567
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV613() {
        let sample = """
    ipv6 access-list extended acl1
    permit 12 host 2001:DB8:0:4::2 host 2620:0db8:0123:4567:89ab:cdef:0123:4567
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 12, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 10, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    func testIosV614() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp host 2001:DB8:0:4::2 neq 33 host 2620:0db8:0123:4567:89ab:cdef:0123:4567
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 33, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 32, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV615() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp ::/0 neq 33 host 2620:0db8:0123:4567:89ab:cdef:0123:4567
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4568".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosV616() {
        let sample = """
    ipv6 access-list extended acl1
    permit tcp ::/0 neq 33 2620:0db8:0123:4567:89ab:cdef:0123:4567/128
    """
        let acl = AccessList(sourceText: sample, deviceType: .iosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4567".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4568".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:0:4::2".ipv6address!, destinationIp: "2620:0db8:0123:4567:89ab:cdef:0123:4566".ipv6address!, sourcePort: 34, destinationPort: 81, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
}
