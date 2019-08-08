//
//  IpRangeV6.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 8/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network


struct IpRangeV6: Equatable {
    
    let minIp: UInt128
    let maxIp: UInt128
    var bitAligned: Bool = true // set to false if initialized with non perfectly aligned ip
    
    var description: String {
        if minIp == maxIp {
            return "\(self.minIp.ipv6)"
        } else {
            return "\(self.minIp.ipv6)-\(self.maxIp.ipv6)"
        }
    }
    
    init(minIp: UInt128, maxIp: UInt128) {
        // caller must guarantee minIp <= maxIp
        self.minIp = minIp
        self.maxIp = maxIp
    }
    
    init?(cidr: String) {
        
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
        guard let ipv6 = IPv6Address(String(ipSubstring)) else { return nil }
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
    }
}
