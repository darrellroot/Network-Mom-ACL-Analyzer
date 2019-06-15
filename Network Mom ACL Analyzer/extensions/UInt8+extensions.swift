//
//  UInt8+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension UInt8 {
    var ipProto: String {
        switch self {
        case 0:
            return "ip"
        case 6:
            return "tcp"
        case 17:
            return "udp"
        default:
            return "\(self)"
        }
    }
}
