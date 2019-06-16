//
//  Socket.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/15/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct Socket {
    let ipProtocol: UInt // 0 means ip
    let sourceIp: UInt
    let sourcePort: UInt?  // always nonoptional for tcp, udp
    let destinationIp: UInt
    let destinationPort: UInt?  // always nonoptional for tcp, udp
    let established: Bool?

    init?(ipProtocol: UInt, sourceIp: UInt, destinationIp: UInt, sourcePort: UInt? = nil, destinationPort: UInt? = nil, established: Bool? = nil) {
        guard ipProtocol < 256 else {
            return nil
        }
        guard sourceIp <= UInt(UInt32.max) else {
            return nil
        }
        guard destinationIp <= UInt(UInt32.max) else {
            return nil
        }
        if let sourcePort = sourcePort {
            guard sourcePort <= UInt(UInt16.max) else {
                return nil
            }
        }
        if let destinationPort = destinationPort {
            guard destinationPort <= UInt(UInt16.max) else {
                return nil
            }
        }
        self.ipProtocol = ipProtocol
        self.sourceIp = sourceIp
        self.destinationIp = destinationIp
        switch ipProtocol {
        case 6: // tcp
            guard sourcePort != nil else {
                return nil
            }
            guard destinationPort != nil else {
                return nil
            }
            self.sourcePort = sourcePort
            self.destinationPort = destinationPort
            self.established = established
        case 17: // udp
            guard sourcePort != nil else {
                return nil
            }
            guard destinationPort != nil else {
                return nil
            }
            self.sourcePort = sourcePort
            self.destinationPort = destinationPort
            self.established = nil
        case 0...255:  // other ip
            self.sourcePort = nil
            self.destinationPort = nil
            self.established = nil
        default:  // invalid, should never get here
            debugPrint("Unknown error in socket")
            return nil
        }
    }
    func reverse() -> Socket? {
        guard let reverseSocket = Socket(ipProtocol: self.ipProtocol, sourceIp: self.destinationIp, destinationIp: self.sourceIp, sourcePort: self.destinationPort, destinationPort: self.sourcePort, established: true) else {
            return nil
        }
        return reverseSocket
    }
}
extension Socket: CustomStringConvertible {
    var description: String {
        switch ipProtocol {
        case 6: // tcp
            guard let sourcePort = sourcePort else {
                return "error no source port in udp socket"
            }
            guard let destinationPort = destinationPort else {
                return "error no source port in udp socket"
            }
            var returnString = "\(self.ipProtocol.ipProto) sourceIp \(self.sourceIp.ipv4) sourcePort \(sourcePort) destinationIp \(self.destinationIp.ipv4) destinationPort \(destinationPort)"
            if let established = self.established, established {
                returnString.append(" established")
                }
            return returnString
        case 17: // udp
            guard let sourcePort = sourcePort else {
                return "error no source port in udp socket"
            }
            guard let destinationPort = destinationPort else {
                return "error no source port in udp socket"
            }
            return "\(self.ipProtocol.ipProto) sourceIp \(self.sourceIp.ipv4) sourcePort \(sourcePort) destinationIp \(self.destinationIp.ipv4) destinationPort \(destinationPort)"
        case 0...255:
            return "\(self.ipProtocol.ipProto) sourceIp \(self.sourceIp.ipv4) destinationIp \(self.destinationIp.ipv4)"
        default:
            return "error: invalid ip proto in socket"
        }
    }
}
