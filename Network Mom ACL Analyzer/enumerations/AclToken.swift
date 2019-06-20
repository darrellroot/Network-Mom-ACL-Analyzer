//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum AclToken: Equatable {
    case accessList
    case permit
    case deny
    case tcp
    case ip
    case udp
    case icmp
    case eq
    case extended
    case objectGroup
    case range
    case host
    case any
    case remark
    case comment
    case gt
    case lt
    case established
    case log
    case fourOctet(UInt)
    case number(UInt)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "access-list":
            self = .accessList
        case "permit":
            self = .permit
        case "deny":
            self = .deny
        case "tcp":
            self = .tcp
        case "icmp":
            self = .icmp
        case "ip":
            self = .ip
        case "udp":
            self = .udp
        case "host":
            self = .host
        case "any":
            self = .any
        case "eq":
            self = .eq
        case "extended":
            self = .extended
        case "object-group":
            self = .objectGroup
        case "range":
            self = .range
        case "gt":
            self = .gt
        case "established":
            self = .established
        case "remark":
            self = .remark
        case "log":
            self = .log
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
