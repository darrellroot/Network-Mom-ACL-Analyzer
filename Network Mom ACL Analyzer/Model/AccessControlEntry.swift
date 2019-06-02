//
//  AccessControlEntry.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct AccessControlEntry {
    let aclAction: AclAction
    let ipVersion: IpVersion
    let ipProtocol: UInt8
    let leastSourceIp: UInt32
    let maxSourceIp: UInt32
    let leastDestIp: UInt32
    let maxDestIp: UInt32
    let leastPort: UInt16
    let maxPort: UInt16
}

struct AccessControlEntryCandidate {
    var aclAction: AclAction?
    var ipVersion: IpVersion?
    var listName: String?
    var ipProtocol: UInt8?
    var leastSourceIp: UInt32?
    var maxSourceIp: UInt32?
    var leastDestIp: UInt32?
    var maxDestIp: UInt32?
    var leastPort: UInt16?
    var maxPort: UInt16?

}
