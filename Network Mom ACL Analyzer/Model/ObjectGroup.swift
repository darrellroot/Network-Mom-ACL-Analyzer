//
//  ObjectGroup.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/29/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

class ObjectGroup {
    var ipRanges: [IpRange] = []
    
    init(ipRange: IpRange) {
        self.ipRanges = [ipRange]
    }
    func append(ipRange: IpRange) {
        self.ipRanges.append(ipRange)
    }
    var count: Int {
        return ipRanges.count
    }
}
