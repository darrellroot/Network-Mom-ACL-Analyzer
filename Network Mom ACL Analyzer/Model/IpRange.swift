//
//  IpRange.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

struct IpRange: CustomStringConvertible, Equatable {
        
    let minIp: UInt128
    let maxIp: UInt128
    var bitAligned: Bool = true // set to false if initialized with non perfectly aligned ip
    let ipVersion: IpVersion
    
    var description: String {
        if minIp == maxIp {
            return "\(self.minIp.ipv4)"
        } else {
            return "\(self.minIp.ipv4)-\(self.maxIp.ipv4)"
        }
    }
    
    
    init(minIp: UInt, maxIp: UInt) {  // requires valid minSourceIp and maxSourceIp
        self.minIp = UInt128(minIp)
        self.maxIp = UInt128(maxIp)
        self.ipVersion = .IPv4
    }
    init(minIp: UInt128, maxIp: UInt128) {
        // caller must guarantee minIp <= maxIp
        self.minIp = minIp
        self.maxIp = maxIp
        //self.ipVersion = nil
        if self.maxIp > UInt128.MAXIPV4 {
            self.ipVersion = .IPv6
        } else {
            self.ipVersion = .Unknown
            debugPrint("unknown ipVersion detected")
        }
    }

    //init?(ip: String, mask: String, type: DeviceType, aclDelegate: ErrorDelegate? = nil, delegateWindow: DelegateWindow? = nil) {
    init?(cidr: String) {
        
        /*func pow(_ x: UInt, _ y: UInt) -> UInt {
            var result: UInt = 1
            for _ in 0..<y {
                result *= x
            }
            return result
        }*/
        func power(_ x: UInt128, _ y: UInt128) -> UInt128 {
            var result: UInt128 = 1
            for _ in 0..<y {
                result = x * result
            }
            return result
        }

        let portions = cidr.split(separator: "/")
        guard portions.count == 2 else { return nil }
        guard let ipSubstring = portions.first else { return nil }
        guard let lengthString = portions.last else { return nil }
        let octets = ipSubstring.split(separator: ".")
        let ipv6 = IPv6Address(String(ipSubstring))
        if ipv6 == nil && octets.count != 4 { return nil }
        if let ipv6 = ipv6 {  //IPv6 case
            self.ipVersion = .IPv6
            guard let length = UInt128(lengthString) else { return nil }
            guard length >= 0 && length <= 128 else { return nil }
            let ip = UInt128(ipv6: ipv6)
            if length == 0 {
                self.minIp = 0
                self.maxIp = UInt128.max
                if ip != 0 {
                    self.bitAligned = false
                }
                return
            } else {
                let numHosts = power(2, 128 - length)
                let remainder = ip % numHosts
                if remainder > 0 {
                    self.bitAligned = false
                }
                self.minIp = ip - remainder
                if self.minIp > 0 {
                    self.maxIp = self.minIp - 1 + numHosts
                } else {
                    self.maxIp = numHosts - 1
                }
                return
            }
        } else {  // IPv4 case
            self.ipVersion = .IPv4
            guard let octet1 = UInt8(octets[0]) else { return nil }
            guard let octet2 = UInt8(octets[1]) else { return nil }
            guard let octet3 = UInt8(octets[2]) else { return nil }
            guard let octet4 = UInt8(octets[3]) else { return nil }
            let passedInAddress: UInt128 = UInt128(octet1) * 256 * 256 * 256 + UInt128(octet2) * 256 * 256 + UInt128(octet3) * 256 + UInt128(octet4)
            guard let length = UInt128(lengthString) else { return nil }
            guard length >= 0 && length <= 32 else { return nil }
            let numHosts = power(UInt128(2),(32 - length))
            let remainder = passedInAddress % numHosts
            let baseAddress: UInt128
            if remainder > 0 {
                bitAligned = false
                baseAddress = passedInAddress - remainder
            } else {
                baseAddress = passedInAddress
            }
            self.minIp = baseAddress
            self.maxIp = baseAddress + numHosts - 1
            return
        }
        
    }
    
    
    init?(ipv4: UInt128, dontCare: UInt128) {
        guard ipv4 >= 0 && ipv4 <= UInt(UInt32.max) else {
            return nil
        }
        guard let numHosts = dontCare.dontCareHosts else {
            return nil
        }
        let remainder = ipv4 % numHosts
        if remainder > 0 { self.bitAligned = false }
        self.minIp = UInt128(ipv4 - remainder)
        self.maxIp = self.minIp + UInt128(numHosts) - 1
        self.ipVersion = .IPv4
        return
    }
    init?(ip: UInt128, netmask: String) {
        guard ip < UInt.MAXIPV4, let maskIp = netmask.ipv4address, let numHosts = maskIp.netmaskHosts else {
            return nil
        }
        let remainder = ip % numHosts
        if remainder > 0 {
            bitAligned = false
            //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
        }
        self.minIp = UInt128(ip - remainder)
        self.maxIp = self.minIp + UInt128(numHosts) - 1
        self.ipVersion = .IPv4
        return
    }
    init?(ip: UInt128, netmask: UInt128) {
        guard let numHosts = netmask.netmaskHosts else {
            return nil
        }
        let remainder = ip % numHosts
        if remainder > 0 {
            bitAligned = false
            //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
        }
        self.minIp = UInt128(ip - remainder)
        self.maxIp = self.minIp + UInt128(numHosts) - 1
        self.ipVersion = .IPv4
        return
    }
    init?(ip: String, netmask: String) {
        guard let ip = ip.ipv4address, let maskIp = netmask.ipv4address, let numHosts = maskIp.netmaskHosts else {
            return nil
        }
        let remainder = ip % numHosts
        if remainder > 0 {
            bitAligned = false
            //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
        }
        self.minIp = UInt128(ip - remainder)
        self.maxIp = self.minIp + UInt128(numHosts) - 1
        self.ipVersion = .IPv4
        return
    }
    init?(ip: String, mask: String, type: DeviceType) {
        if ip == "host", let ipv4 = mask.ipv4address {
            self.minIp = UInt128(ipv4)
            self.maxIp = UInt128(ipv4)
            self.ipVersion = .IPv4
            return
        } else if type == .asa {
            if let ipv4 = ip.ipv4address, let maskIp = mask.ipv4address, let numHosts = maskIp.netmaskHosts {
                self.ipVersion = .IPv4
                let remainder = ipv4 % numHosts
                if remainder > 0 {
                    bitAligned = false
                    //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
                }
                self.minIp = UInt128(ipv4 - remainder)
                self.maxIp = self.minIp + UInt128(numHosts) - 1
                return
            }
        }
        return nil
    }
}
