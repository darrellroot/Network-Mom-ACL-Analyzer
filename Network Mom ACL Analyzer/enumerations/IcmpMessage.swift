//
//  IcmpMessage.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/16/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct IcmpMessage {
    let type: UInt
    let code: UInt?
    
    init?(type: UInt, code: UInt? = nil) {
        guard type < 256 else {
            return nil
        }
        if let code = code {
            guard code < 256 else {
                return nil
            }
        }
        self.type = type
        self.code = code
    }
    init?(message: String) {
        switch message {
        case "administratively-prohibited":
            break
        case "alternate-address":
            break
        case "conversion-error":
            break
        case "dod-host-prohibited":
            break
        case "dod-net-prohibited":
            break
        case "echo":
            break
        case "echo-reply":
            break
        case "general-parameter-problem":
            break
        case "host-isolated":
            break
        case "host-precedence-unreachable":
            break
        case "host-redirect":
            break
        case "host-tos-redirect":
            break
        case "host-tos-unreachable":
            break
        case "host-unknown":
            break
        case "host-unreachable":
            break
        case "information-reply":
            break
        case "information-request":
            break
        case "mask-reply":
            break
        case "mask-request":
            break
        case "mobile-redirect":
            break
        case "net-redirect":
            break
        case "net-tos-redirect":
            break
        case "net-tos-unreachable":
            break
        case "net-unreachable":
            break
        case "network-unknown":
            break
        case "no-room-for-option":
            break
        case "option-missing":
            break
        case "packet-too-big":
            break
        case "parameter-problem":
            break
        case "port-unreachable":
            break
        case "precedence-unreachable":
            break
        case "protocol-unreachable":
            break
        case "reassembly-timeout":
            break
        case "redirect":
            break
        case "router-advertisement":
            break
        case "router-solicitation":
            break
        case "source-quench":
            break
        case "source-route-failed":
            break
        case "time-exceeded":
            break
        case "timestamp-reply":
            break
        case "timestamp-request":
            break
        case "traceroute":
            break
        case "ttl-exceeded":
            break
        case "unreachable":
            break
        default:
            return nil
        }
        //MARK: TODO
        debugPrint("TODO: icmpMessage.swift not fully implemented")
        self.type = 1
        self.code = 1
    }
}
