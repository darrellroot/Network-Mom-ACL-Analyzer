//
//  String+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension String {
    var ipv4address: UInt? {
        let octets = self.split(separator: ".")
        guard octets.count == 4 else { return nil }
        guard let octet1 = UInt8(octets[0]) else { return nil }
        guard let octet2 = UInt8(octets[1]) else { return nil }
        guard let octet3 = UInt8(octets[2]) else { return nil }
        guard let octet4 = UInt8(octets[3]) else { return nil }
        let answer: UInt = UInt(octet1) * 256 * 256 * 256 + UInt(octet2) * 256 * 256 + UInt(octet3) * 256 + UInt(octet4)
        return answer
    }
    var tcpPort: UInt? {
        switch self {
        case "bgp":
            return 179
        case "domain":
            return 53
        case "exec":
            return 512
        case "ftp":
            return 21
        case "ftp-data":
            return 20
        case "https":
            return 443
        case "mms":
            return 1755
        case "nfs":
            return 2049
        case "smtp":
            return 25
        case "ssh":
            return 22
        case "tacacs":
            return 49
        case "telnet":
            return 23
        case "www":
            return 80
        default:
            return nil
        }
    }
    var udpPort: UInt? {
        switch self {
        case "bootpc":
            return 68
        case "bootps":
            return 67
        case "domain":
            return 53
        case "mms":
            return 1755
        case "netbios-dgm":
            return 138
        case "netbios-ns":
            return 137
        case "netbios-ss":
            return 139
        case "nfs":
            return 2049
        case "ntp":
            return 123
        case "snmp":
            return 161
        case "snmptrap":
            return 162
        case "tacacs":
            return 49
        case "tftp":
            return 69
        case "wccp":
            return 2048
        default:
            return nil
        }
    }
}
