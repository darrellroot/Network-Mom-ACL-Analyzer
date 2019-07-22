//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum IosToken: Equatable {
    case unsupported(String)
    case accessList
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case objectGroup
    case portOperator(PortOperator)
    case comment
    case log
    case established
    case fourOctet(UInt)
    case number(UInt)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "dynamic","timeout","precedence","dscp","tos","time-range","fragments":
            self = .unsupported(string)
        case "access-list":
            self = .accessList
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "deny":
            self = .action(.deny)
        case "log", "log-input":
            self = .log
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
        case "object-group":
            self = .objectGroup
        case "ahp","eigrp","esp","gre","icmp","igmp","igrp","ip","ipv4","ipinip","nos","ospf","pcp","pim","tcp","udp":
            if let ipProtocol = string.iosIpProtocol {
                self = .ipProtocol(ipProtocol)
            } else {
                return nil
            }
            
        default:
            if let number = UInt(string) {
                self = .number(number)
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
