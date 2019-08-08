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
        let ace = AccessControlEntryV6(line: "permit tcp 2001:db8::/32 eq domain 2001:3:4::4/48 eq www", deviceType: .ios, linenum: 5, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace?.sourcePort[0].maxPort == 53)
        XCTAssert(ace?.destPort[0].minPort == 80)
    }
    func testV6() {
        let address = IPv6Address("2001:0db8::3")!
        let oneTwentyEight = UInt128(ipv6: address)
        
        XCTAssert(oneTwentyEight.ipv6 == "2001:0db8:0000:0000:0000:0000:0000:0003")
    }
    func testIpRangeV6() {
        let ipRange = IpRangeV6(cidr: "2001:0db8::3/32")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == false)
        debugPrint(ipRange)
    }
    func testIpRangeV6d() {
        let ipRange = IpRangeV6(cidr: "2001:0db8::/32")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == true)
        debugPrint(ipRange)
    }

    func testIpRangeV6a() {
        let ipRange = IpRangeV6(cidr: "::1/127")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == false)
        //debugPrint(ipRange)
    }
    func testIpRangeV6b() {
        let ipRange = IpRangeV6(cidr: "::2/127")
        XCTAssert(ipRange != nil)
        XCTAssert(ipRange?.bitAligned == true)
        //debugPrint(ipRange)
    }

}
