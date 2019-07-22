//
//  IpRange.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct IpRange: CustomStringConvertible, Equatable {
        
    let minIp: UInt
    let maxIp: UInt
    var bitAligned: Bool = true // set to false if initialized with non perfectly aligned ip
    
    var description: String {
        if minIp == maxIp {
            return "\(self.minIp.ipv4)"
        } else {
            return "\(self.minIp.ipv4)-\(self.maxIp.ipv4)"
        }
    }
    
    
    init(minIp: UInt, maxIp: UInt) {  // requires valid minSourceIp and maxSourceIp
        self.minIp = minIp
        self.maxIp = maxIp
    }
    //init?(ip: String, mask: String, type: DeviceType, aclDelegate: ErrorDelegate? = nil, delegateWindow: DelegateWindow? = nil) {
    init?(cidr: String) {
        
        func pow(_ x: UInt, _ y: UInt) -> UInt {
            var result: UInt = 1
            for _ in 0..<y {
                result *= x
            }
            return result
        }

        let portions = cidr.split(separator: "/")
        guard portions.count == 2 else { return nil }
        guard let ip = portions.first else { return nil }
        guard let lengthString = portions.last else { return nil }
        let octets = ip.split(separator: ".")
        guard octets.count == 4 else { return nil }
        guard let octet1 = UInt8(octets[0]) else { return nil }
        guard let octet2 = UInt8(octets[1]) else { return nil }
        guard let octet3 = UInt8(octets[2]) else { return nil }
        guard let octet4 = UInt8(octets[3]) else { return nil }
        let passedInAddress: UInt = UInt(octet1) * 256 * 256 * 256 + UInt(octet2) * 256 * 256 + UInt(octet3) * 256 + UInt(octet4)
        guard let length = UInt(lengthString) else { return nil }
        guard length >= 0 && length <= 32 else { return nil }
        let numHosts = pow(UInt(2),(32 - length))
        let remainder = passedInAddress % numHosts
        let baseAddress: UInt
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
    
    init?(ipv4: UInt, dontCare: UInt) {
        guard ipv4 >= 0 && ipv4 <= UInt(UInt32.max) else {
            return nil
        }
        guard let numHosts = dontCare.dontCareHosts else {
            return nil
        }
        let remainder = ipv4 % numHosts
        if remainder > 0 { self.bitAligned = false }
        self.minIp = ipv4 - remainder
        self.maxIp = self.minIp + numHosts - 1
        return
    }
    init?(ip: UInt, netmask: String) {
        guard ip < UInt.MAXIPV4, let maskIp = netmask.ipv4address, let numHosts = maskIp.netmaskHosts else {
            return nil
        }
        let remainder = ip % numHosts
        if remainder > 0 {
            bitAligned = false
            //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
        }
        self.minIp = ip - remainder
        self.maxIp = self.minIp + numHosts - 1
        return
    }
    init?(ip: UInt, netmask: UInt) {
        guard let numHosts = netmask.netmaskHosts else {
            return nil
        }
        let remainder = ip % numHosts
        if remainder > 0 {
            bitAligned = false
            //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
        }
        self.minIp = ip - remainder
        self.maxIp = self.minIp + numHosts - 1
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
        self.minIp = ip - remainder
        self.maxIp = self.minIp + numHosts - 1
        return
    }
    init?(ip: String, mask: String, type: DeviceType) {
        if ip == "host", let ipv4 = mask.ipv4address {
            self.minIp = ipv4
            self.maxIp = ipv4
            return
        } else if type == .asa {
            if let ipv4 = ip.ipv4address, let maskIp = mask.ipv4address, let numHosts = maskIp.netmaskHosts {
                let remainder = ipv4 % numHosts
                if remainder > 0 {
                    bitAligned = false
                    //aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary", delegateWindow: delegateWindow)
                }
                self.minIp = ipv4 - remainder
                self.maxIp = self.minIp + numHosts - 1
                return
            }
        }
        return nil
    }
}
