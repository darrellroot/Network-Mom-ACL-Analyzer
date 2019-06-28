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
}
