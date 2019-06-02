//
//  String+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension String {
    var ipv4address: UInt32? {
        let octets = self.split(separator: ".")
        guard octets.count == 4 else { return nil }
        guard let octet1 = UInt8(octets[0]) else { return nil }
        guard let octet2 = UInt8(octets[1]) else { return nil }
        guard let octet3 = UInt8(octets[2]) else { return nil }
        guard let octet4 = UInt8(octets[3]) else { return nil }
        let answer: UInt32 = UInt32(octet1) * 256 * 256 * 256 + UInt32(octet2) * 256 * 256 + UInt32(octet3) * 256 + UInt32(octet4)
        return answer
    }
    
}
