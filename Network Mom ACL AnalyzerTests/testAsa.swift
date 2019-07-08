//
//  testAsa.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest

class testAsa: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    func testAsaMultiNames() {
        let sample = """
        access-list OUT1 extended permit ip host 209.168.200.3 any
        access-list OUT2 extended permit ip host 209.168.200.4 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.names.count == 2)
    }

    func testAsaObject1() {
        let sample = """
        access-list ACL_IN extended permit ip any any
        access-list ACL_IN extended permit object service-obj-http any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.count == 1)
        XCTAssert(acl.accessControlEntries[0].sourceIp[0].minIp == 0)
    }

    func testAsaRemark1() {
        let sample = """
        access-list OUT remark - this is the inside admin address
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.count == 2)
        XCTAssert(acl.accessControlEntries[0].destIp[0].minIp == 0)
        XCTAssert(acl.accessControlEntries[1].sourceIp[0].maxIp == "209.168.200.4".ipv4address!)
    }
    func testAsaIosReject1() {
        let sample = """
        access-list OUT extended permit ip host 209.168.200.3 any
        access-list OUT remark - this is the hr admin address
        access-list OUT extended permit ip host 209.168.200.4 any
        access-list OUT remark - this is the inside admin address
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 0)
    }

    func testAsaReject() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace == nil)
    }
    func testAsaPortMatch() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == "209.165.201.29".ipv4address)
        XCTAssert(ace.destPort[0].minPort == 80)
        XCTAssert(ace.destPort[0].maxPort == 80)
    }
    func testAsaIosReject2() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 eq www"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8)
        XCTAssert(ace == nil)
    }
    func testAsaAce1() {
        let line = "access-list outside_in extended permit ip any host 172.16.1.2"
        guard let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == 0)
        XCTAssert(ace.sourceIp[0].maxIp == "255.255.255.255".ipv4address)
        guard let destIp = "172.16.1.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == destIp)
    }
    func testAsaIcmp() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace!.ipProtocols.first == 1)
        XCTAssert(ace!.sourceIp[0].minIp == 0)
    }
    func testAsaIosIcmpReject() {
        let line = "access-list abc extended permit icmp any any echo"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8)
        XCTAssert(ace == nil)
    }
    
    func testAsaPortNe() {
        let line = "access-list ACL_IN extended deny tcp any host 209.165.201.29 ne www"
        let ace = AccessControlEntry(line: line, deviceType: .asa, linenum: 8)
        XCTAssert(ace != nil)

        guard let socket = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 44, established: false) else {
            XCTAssert(false)
            return
        }
        let result = ace!.analyze(socket: socket)
        XCTAssert(result == .deny)
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result2 = ace!.analyze(socket: socket2)
        XCTAssert(result2 == .neither)
        
        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "209.165.201.28".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 81, established: false) else {
            XCTAssert(false)
            return
        }
        let result3 = ace!.analyze(socket: socket3)
        XCTAssert(result3 == .deny)

    }
    func testIpRange() {
        let ip = "209.165.200.0".ipv4address
        XCTAssert(ip != nil)
        let maskIp = "255.255.255.0".ipv4address
        XCTAssert(maskIp != nil)
        let numHosts = maskIp?.netmaskHosts
        XCTAssert(numHosts != nil)
        let ipRange = IpRange(ip: "209.165.200.0", mask: "255.255.255.0", type: .asa)
        XCTAssert(ipRange != nil)
    }
    func testAsaSourceObjectGroup() {
        let sample = """
        object-group network denied
            network-object host 10.1.1.4
            network-object host 10.1.1.78
            network-object host 10.1.1.89
        access-list ACL_IN extended deny tcp object-group denied any eq www
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.accessControlEntries.count == 1)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    func testAsaObjectGroupServiceSource1() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq radius
            port-object eq radius-acct
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services1 any
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupServices.count == 3)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 44, established: false)!
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    
    func testAsaObjectGroupServiceSource2() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq domain
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services2 any
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupServices.count == 3)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 44, established: false)!
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
    }
    
    func testPortObjectLdap() {
        let sample = """
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupServices["services3"]!.portRanges.count == 1)
    }
    
    func testAsaObjectGroupServiceDest() {
        let sample = """
        object-group service services1 tcp-udp
            description DNS Group
            port-object eq domain
        object-group service services2 udp
            description RADIUS Group
            port-object eq radius
            port-object eq radius-acct
        object-group service services3 tcp
            description LDAP Group
            port-object eq ldap
        access-list ACL_IN extended permit tcp any object-group services1 any object-group services3
        """
        let iosacl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(iosacl.objectGroupServices.count == 0)
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupServices.count == 3)
        XCTAssert(acl.objectGroupServices["services3"] != nil)
        XCTAssert(acl.getObjectGroupService("services3") != nil)
        let service = acl.getObjectGroupService("services3")
        XCTAssert(service!.portRanges.count == 1)
        let socket = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 389, established: false)!
        XCTAssert(acl.accessControlEntries.count == 1)
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "131.252.209.11".ipv4address!, destinationIp: "198.133.212.39".ipv4address!, sourcePort: 53, destinationPort: 390, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testObjectGroupNetmask() {
        let sample = """
        object-group network eng
            network-object 2.1.1.0 255.255.255.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupNetworks["eng"]!.ipRanges.count == 1)
    }
    func testAsaObjectGroupNetmask() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.1.0 255.255.255.0
        access-list ACL extended permit tcp 3.2.0.0 255.255.0.0 object-group eng object-group services1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "2.1.2.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "3.2.3.3".ipv4address!, destinationIp: "2.1.1.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
    }
    
    func testAsaEstablishedError() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.0.0 255.255.128.0
        access-list ACL extended permit tcp object-group eng 3.2.0.0 255.255.0.0 object-group services1 established
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    
    func testAsaDuplicateObjectGroup() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network services1
            network-object host 1.1.1.1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupNetworks.count == 0)
        XCTAssert(acl.objectGroupServices.count == 1)

    }
    
    func testAsaProtocolObject1() {
        let sample = """
        object-group protocol tcp_udp_icmp
            protocol-object tcp
            protocol-object icmp
            protocol-object udp
        access-list 101 extended permit object-group tcp_udp_icmp 1.1.63.0 255.255.192.0 2.2.4.0 255.255.254.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.0.3".ipv4address!, destinationIp: "2.2.4.31".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 1, sourceIp: "1.1.63.3".ipv4address!, destinationIp: "2.2.5.31".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 1, sourceIp: "1.1.64.3".ipv4address!, destinationIp: "2.2.4.31".ipv4address!, sourcePort: nil, destinationPort: nil, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
    }
    
    func testAsaProtocolObject() {
        let sample = """
        object-group protocol blork
            protocol-object tcp
            protocol-object 8
            protocol-object udp
            protocol-object icmp
            access-list zoom extended permit object-group blork 10.1.4.0 255.255.252.0 20.1.8.0 255.248.0.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 8, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 8, sourceIp: "10.1.8.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testAsaNestedProtocolObject() {
        let sample = """
        object-group protocol alpha
            protocol-object tcp
            protocol-object 8
        object-group protocol beta
            protocol-object udp
            protocol-object icmp
        object-group protocol nest
            group-object alpha
            group-object beta
        access-list zoom extended permit object-group nest 10.1.4.0 255.255.252.0 20.1.8.0 255.248.0.0
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 8, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 7, sourceIp: "10.1.7.8".ipv4address!, destinationIp: "20.1.15.3".ipv4address!, sourcePort: nil, destinationPort: nil, established: nil)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testsaNestedObjectService1() {
        let sample = """
        object-group service alpha tcp
            port-object eq 1
            port-object range 2 5
        object-group service beta tcp
            port-object eq 7
            port-object range 7 9
        object-group service gamma tcp
            group-object alpha
            group-object beta
        access-list crazy extended permit tcp 10.1.16.0 255.255.240.0 20.1.32.0 255.255.224.0 object-group gamma
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 5, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 6, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testAsaNestedObjectServiceInvalid1() {
        let sample = """
        object-group service alpha tcp
            port-object eq 1
            port-object range 2 5
        object-group service beta udp
            port-object eq 7
            port-object range 7 9
        object-group service gamma tcp
            group-object alpha
            group-object beta
        access-list crazy extended permit tcp 10.1.16.0 255.255.240.0 20.1.32.0 255.255.224.0 object-group gamma
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 5, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.31.33".ipv4address!, destinationIp: "20.1.63.3".ipv4address!, sourcePort: 80, destinationPort: 8, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testComplexObject1() {
        let sample = """
        object-group protocol bob
            protocol-object tcp
            protocol-object udp
        object-group service alpha tcp
            port-object eq 1
            port-object eq 2
        object-group service beta tcp-udp
            port-object eq 1
            port-object eq 2
        access-list 101 extended permit object-group bob 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 object-group alpha
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    func testComplexObject2() {
        let sample = """
        object-group protocol bob
            protocol-object tcp
            protocol-object udp
        object-group service alpha tcp
            port-object eq 1
            port-object eq 2
        object-group service beta tcp-udp
            port-object eq 1
            port-object eq 2
        access-list 101 extended permit object-group bob 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0 object-group beta
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.3".ipv4address!, destinationIp: "2.2.2.3".ipv4address!, sourcePort: 80, destinationPort: 1, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
    }

    
    func testAsaNestedObjectNetwork1() {
        let sample = """
        object-group network eng
            network-object host 10.1.1.5
            network-object host 10.1.1.9
            network-object host 10.1.1.89
        object-group network hr
            network-object host 10.1.2.8
            network-object host 10.1.2.12
            network-object 10.2.128.0 255.255.254.0
        object-group network finance
            network-object host 10.1.4.89
            network-object host 10.1.4.100
        object-group network admin
            group-object eng
            group-object hr
            group-object finance
        access-list ACL_IN extended permit ip object-group admin host 209.165.201.29
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.2.129.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 6, sourceIp: "10.2.130.9".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
    }
    
    
    func testAsaObjectGroupDestNetmask() {
        let sample = """
        object-group service services1 tcp
            description DNS Group
            port-object eq domain
            port-object eq ssh
        object-group network eng
            network-object host 1.1.1.1
            network-object 2.1.0.0 255.255.128.0
        access-list ACL extended permit tcp object-group eng 3.2.0.0 255.255.0.0 object-group services1
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "2.1.33.3".ipv4address!, destinationIp: "3.2.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }

    
    func testAsaObjectGroupAcl() {
        let sample = """
        object-group network denied
            network-object host 10.1.1.4
            network-object host 10.1.1.78
            network-object host 10.1.1.89
        object-group network web
            network-object host 209.165.201.29
            network-object host 209.165.201.16
            network-object host 209.165.201.78
            network-object 209.165.200.0 255.255.255.0
        access-list ACL_IN extended deny tcp object-group denied object-group web eq www
        access-list ACL_IN extended permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .asa)
        XCTAssert(acl.objectGroupNetworks.count == 2)
        XCTAssert(acl.objectGroupNetworks["denied"]!.count == 3)
        XCTAssert(acl.objectGroupNetworks["web"]!.count == 4)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        guard let socket = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result == .deny)
        
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.4".ipv4address!, destinationIp: "209.165.200.36".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "10.1.1.5".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
    }
    
    func testAsaPermitAny() {
        let ace = AccessControlEntry(line: "access-list ACL_IN extended permit ip any any", deviceType: .asa, linenum: 3)
        guard let socket3 = Socket(ipProtocol: 6, sourceIp: "10.1.1.5".ipv4address!, destinationIp: "209.165.201.29".ipv4address!, sourcePort: 33, destinationPort: 80, established: false) else {
            XCTAssert(false)
            return
        }
        let result = ace?.analyze(socket: socket3)
        XCTAssert(result == .permit)
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
