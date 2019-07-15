//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum NxAclToken: Equatable {
    case unsupported(String)
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case addrgroup
    case portgroup
    case portOperator(PortOperator)
    case comment
    case log
    case established
    case fourOctet(UInt)
    case cidr(IpRange)
    case number(UInt)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "dscp","packet-length","precedence","time-range", "ack","fin","psh","rst","syn","urg", "dvmrp","host-query","host-report","trace","precedence","packet-length":
            self = .unsupported(string)
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "addrgroup":
            self = .addrgroup
        case "portgroup":
            self = .portgroup
        case "deny":
            self = .action(.deny)
        case "log":
            self = .log
        case "ahp","eigrp","esp","gre","icmp","igmp","ip","nos","ospf","pcp","pim","tcp","udp":
            if let ipProtocol = string.nxosIpProtocol {
                self = .ipProtocol(ipProtocol)
            } else {
                return nil
            }
        case "any":
            self = .any
        case "host":
            self = .host
        case "eq","gt","lt","neq","range":
            if let portOperator = PortOperator(string) {
                self = .portOperator(portOperator)
            } else {
                return nil
            }
        case "established","est":
            self = .established
        default:
            if let number = UInt(string) {
                self = .number(number)
            } else if let ipRange = IpRange(cidr: string) {
                self = .cidr(ipRange)
            } else if let ipv4Address = string.ipv4address {
                self = .fourOctet(ipv4Address)
            } else if string.first == "!" || string.first == "#" || string.first == ";" || string.first == ":" {
                self = .comment
            } else  {
                self = .name(string)
            }
        }
    }
}
