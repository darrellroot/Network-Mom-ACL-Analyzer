//
//  AccessList.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

class AccessList {
    let sourceText: String
    var accessControlEntries: [AccessControlEntry] = []
    let accessListType: MaskType
    
    var count: Int {
        return accessControlEntries.count
    }
    
    init(sourceText: String) {
        self.sourceText = sourceText
        var linenum = 0
        
        // identify type of acl
        var dontCareBitTotal = 0
        var netmaskTotal = 0
        var eitherTotal = 0
        var accessListType: MaskType
        for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            for word in line.components(separatedBy: NSCharacterSet.whitespaces) {
                if let ipv4address = word.ipv4address {
                    if let maskType = ipv4address.maskType {
                        switch maskType {
                            
                        case .dontCareBit:
                            dontCareBitTotal += 1
                        case .netmask:
                            netmaskTotal += 1
                        case .either:
                            eitherTotal += 1
                        }
                    }
                }
            }
        }
        debugPrint("Number of Dont Care Bits found: \(dontCareBitTotal)")
        debugPrint("Number of netmasks found: \(netmaskTotal)")
        debugPrint("Number of either found: \(eitherTotal)")
        if dontCareBitTotal > netmaskTotal {
            accessListType = .dontCareBit
        } else {
            accessListType = .netmask
        }
        
        lineLoop: for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            linenum = linenum + 1
            if line.isEmpty {
                debugPrint("line \(linenum) is empty")
                continue lineLoop
            }
            if let accessControlEntry = AccessControlEntry(line: line, type: accessListType) {
                accessControlEntries.append(accessControlEntry)
            }
        }
        self.accessListType = accessListType
    }
}
