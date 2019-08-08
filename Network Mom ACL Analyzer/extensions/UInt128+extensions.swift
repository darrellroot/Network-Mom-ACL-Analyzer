//
//  UInt128+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 8/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

extension UInt128 {
    var ipv6: String {
        var runningValue = self
        var output: String = ""
        for position: UInt128 in 0..<32 {
            let lastDigitValue = Int(runningValue % 16)
            runningValue = runningValue / 16
            let character = String(format: "%x",lastDigitValue)
            output = "\(character)\(output)"
            if position % 4 == 3 && position != 0 && position != 31 {
                output = ":\(output)"
            }
        }
        return output
    }
    
    init(ipv6: IPv6Address) {
        let data = ipv6.rawValue
        guard data.count == 16 else {
            fatalError("ipv6 data does not have 16 bytes")
        }
        var total: UInt128 = 0
        for byte in data {
            total = total * 256
            total = total + UInt128(byte)
        }
        self = total
    }
}
