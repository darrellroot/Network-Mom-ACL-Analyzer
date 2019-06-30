//
//  IpRange.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct IpRange: CustomStringConvertible {
    let minIp: UInt
    let maxIp: UInt
    
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
    init?(ip: String, mask: String, type: DeviceType, aclDelegate: ErrorDelegate? = nil) {
        if ip == "host", let ipv4 = mask.ipv4address {
            self.minIp = ipv4
            self.maxIp = ipv4
            return
        } else if type == .asa {
            if let ipv4 = ip.ipv4address, let maskIp = mask.ipv4address, let numHosts = maskIp.netmaskHosts {
                let remainder = ipv4 % numHosts
                if remainder > 0 {
                    aclDelegate?.report(severity: .warning, message: "\(ip) \(mask) Destination IP not on netmask or bit boundary")
                }
                self.minIp = ipv4 - remainder
                self.maxIp = self.minIp + numHosts - 1
                return
            }
        }
        return nil
    }
}
