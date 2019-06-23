//
//  UnsupportedFeatureTests.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/22/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class UnsupportedFeatureTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }
    
    func testAsaPortNe() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 ne www"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace == nil)
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
