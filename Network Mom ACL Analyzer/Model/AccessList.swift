//
//  AccessList.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

class AccessList: AceInfoDelegate {
    
    let sourceText: String
    var accessControlEntries: [AccessControlEntry] = []
    var deviceType: DeviceType
    var names: Set<String> = []
    var delegate: AclErrorDelegate?
    
    var count: Int {
        return accessControlEntries.count
    }
    
    init(sourceText: String, deviceType: DeviceType, delegate: AclErrorDelegate? = nil) {
        self.sourceText = sourceText
        self.delegate = delegate
        self.deviceType = deviceType
        var linenum = 0
        
        /*// identify type of acl
        var dontCareBitTotal = 0
        var netmaskTotal = 0
        var eitherTotal = 0
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
        }*/
        /*delegate?.report(severity: .notification, message: "Number of Dont Care Bits found: \(dontCareBitTotal)")
        delegate?.report(severity: .notification, message: "Number of netmasks found: \(netmaskTotal)")
        delegate?.report(severity: .notification, message: "Number of either found: \(eitherTotal)")
        if dontCareBitTotal > netmaskTotal {
            self.accessListType = .dontCareBit
        } else if netmaskTotal > dontCareBitTotal {
            self.accessListType = .netmask
        } else {
            self.accessListType = .either
        }*/
        
        lineLoop: for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            linenum = linenum + 1
            if line.isEmpty {
                //delegate?.report(severity: .notification, message: "line is empty", line: linenum)
                continue lineLoop
            }
            let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            
            if line.starts(with: "ip access-list extended") {
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let aclName = words[safe: 3] {
                    names.insert(aclName)
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found")
                    }
                }
                continue lineLoop
            }
            
            if let accessControlEntry = AccessControlEntry(line: line, deviceType: deviceType, linenum: linenum, infoDelegate: self, errorDelegate: delegate) {
                accessControlEntries.append(accessControlEntry)
            }
        }
    }
    public func analyze(socket: Socket, delegate: AclErrorDelegate? = nil) -> AclAction {
        var aclAction: AclAction? = nil
        for (lineNumber,accessControlEntry) in accessControlEntries.enumerated() {
            let aceAction = accessControlEntry.analyze(socket: socket)
            switch aceAction {
            case .neither:
                continue
            case .permit, .deny:
                if aclAction == nil {
                    // first match in acl
                    aclAction = aceAction
                    delegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: lineNumber)
                    //delegate?.report(severity: .result, message: "FIRST MATCH \(aclAction)", line: lineNumber)
                } else {
                    // later match in acl
                    delegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: lineNumber)
                    //delegate?.report(severity: .result, message: "Also matches \(aclAction)", line: lineNumber)
                }
            }
        }
        guard let finalAclAction = aclAction else {
            // no match found, implicit deny
            delegate?.report(severity: .result, message: "No Match Found, implicit \(AclAction.deny)")
            return .deny
        }
        return finalAclAction
    }
    func foundName(_ name: String) {
        names.insert(name)
        if names.count > 1 {
            self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found")
        }
    }
}
