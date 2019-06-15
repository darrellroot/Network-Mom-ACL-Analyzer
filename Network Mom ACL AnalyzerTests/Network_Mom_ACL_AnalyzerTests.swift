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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.2 0.0.0.1", type: .dontCareBit, linenum: 1) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp 3.7.4.18 0.0.0.3 2.2.2.3 0.0.0.1", type: .dontCareBit, linenum: 2) else {
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
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2 established", type: .dontCareBit, linenum: 4) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == true)
    }
    
    func testNotEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2", type: .dontCareBit, linenum: 4) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == false)
    }

    func testBitBoundaryDest() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.3 0.0.0.1", type: .dontCareBit, linenum: 3) else {
            XCTAssert(false)
            return
        }
        guard let destip = "2.2.2.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.minDestIp == destip)
    }


    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
