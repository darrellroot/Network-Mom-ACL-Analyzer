//
//  TestIosXE.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 7/27/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class TestIosXE: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testIosxeLog1() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }

    func testIosxe1() {
        let sample = """
        ip access-list extended telnetting
         remark Do not allow host1 subnet to telnet out
         permit tcp host 172.16.2.88 any eq telnet
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "172.16.2.88".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "172.16.2.88".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testIosXe2() {
        let sample = """
        ip access-list extended acl1
        deny ip 172.18.0.0 0.0.255.255 host 172.16.40.10 log
        permit tcp any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "172.18.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 21, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .deny)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "172.18.3.3".ipv4address!, destinationIp: "172.16.40.11".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)

        let socket3 = Socket(ipProtocol: 6, sourceIp: "172.17.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

        let socket4 = Socket(ipProtocol: 17, sourceIp: "172.17.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .deny)
    }
    func testIosNumbered1() {
        let sample = """
        access-list 107 remark allow Telnet packets from any source to network 172.69.0.0 (headquarters)
        access-list 107 permit tcp any 172.69.0.0 0.0.255.255 eq telnet
        access-list 107 remark deny all other TCP packets
        access-list 107 deny tcp any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.69.3.3".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.69.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.68.3.3".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXe3() {
        let sample = """
        ip access-list extended marketing-group
         permit tcp any 172.26.0.0 0.0.255.255 eq telnet
         deny tcp any any
         permit icmp any any
         permit udp any 172.26.0.0 0.0.255.255 lt 1024
         deny ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 5)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 1024, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXe4() {
        let sample = """
        ip access-list extended telnetting
         remark Do not allow user1 subnet to telnet out
         deny tcp 172.20.0.0 0.0.255.255 any eq telnet
         remark Allow Top subnet to telnet out
         permit tcp 172.33.0.0 0.0.255.255 any eq telnet
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXe5() {
        let sample = """
        ip access-list extended acl1
         permit tcp any 172.28.0.0 0.0.255.255 gt 1023
         permit tcp any host 172.28.1.2 eq 25
         permit icmp any 172.28.0.0 255.255.255.255
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 1024, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 1023, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXe6() {
        let sample = """
        access-list 102 permit tcp any 172.18.0.0 0.0.255.255 established
        access-list 102 permit tcp any host 172.18.1.2 eq 25
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.3".ipv4address!, sourcePort: 33, destinationPort: 25, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXe7() {
        let sample = """
        ip access-list extended no-web
         remark Do not allow w1 to browse the web
         deny tcp host 172.20.3.85 any eq www
         remark Do not allow w2 to browse the web
         deny tcp host 172.20.3.13 any eq www
         remark Allow others on our network to browse the web
         permit tcp 172.20.0.0 0.0.255.255 any eq www
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.3.85".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.3.86".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    
    
    func testIosXeObject1() {
        let sample = """
        object-group my-nested-object-group
          host 1.1.1.1
        object-group network my-network-object-group
          description test engineers
          host 209.165.200.237
          209.165.200.241 255.255.255.224
          group-object my-nested-object-group
        object-group my-nested-service-object-group
          tcp source eq 30
          tcp eq 31
          tcp source eq 32 eq 33
        object-group service my-service-object-group
          description test engineers
          ahp
          tcp-udp range 2000 2005
          icmp conversion-error
          group-object my-nested-service-object-group
        ip access-list extended nomarketing
          remark protect server by denying access from the Marketing network
        permit object-group my-service-object-group object-group my-network-object-group host 1.1.1.1 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.245".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 80, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 43, destinationPort: 31, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 32, destinationPort: 33, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    func testIosXeObject2() {
        let sample = """
        object-group network my-network-object-group
            description test engineers
            host 209.165.200.237
            host 209.165.200.238
            209.165.200.241 255.255.255.224
        object-group network my-company-network
            host 209.165.200.242
            209.165.200.225 255.255.255.224
            group-object my-network-object-group
        object-group service my-service-object-group
            icmp echo
            tcp smtp
            tcp telnet
            tcp source range 50 65535 telnet
            tcp source 2000 ftp
            udp domain
            tcp-udp range 2000 2005
            group-object my-nested-object-group
        ip access-list extended my-ogacl-policy
            permit object-group my-service-object-group object-group my-network-object-group any
            deny tcp any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.236".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 26, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.241".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 50, destinationPort: 23, established: false)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }

    }
}
