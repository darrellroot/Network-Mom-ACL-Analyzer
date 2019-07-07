//
//  IpRange.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct PortRange: CustomStringConvertible {
    let minPort: UInt
    let maxPort: UInt
    
    var description: String {
        if minPort == maxPort {
            return "\(self.minPort)"
        } else {
            return "\(self.minPort)-\(self.maxPort)"
        }
    }
    
    init?(minPort: UInt, maxPort: UInt) {  // requires valid minSourceIp and maxSourceIp
        guard minPort >= 0 && maxPort >= 0 && minPort <= 65535 && maxPort <= 65535 && minPort <= maxPort else {
            return nil
        }
        self.minPort = minPort
        self.maxPort = maxPort
    }
}
