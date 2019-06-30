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
    var deviceType: DeviceType
    var names: Set<String> = []
    var delegate: ErrorDelegate?
    var objectGroups = [String:ObjectGroup]()

    var count: Int {
        return accessControlEntries.count
    }
    
    init(sourceText: String, deviceType: DeviceType, delegate: ErrorDelegate? = nil) {
        self.sourceText = sourceText
        self.delegate = delegate
        self.deviceType = deviceType
        var linenum = 0
        var objectName: String? = nil  //non-nil if we are in object-group mode
        
        lineLoop: for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            linenum = linenum + 1
            if line.isEmpty {
                //delegate?.report(severity: .notification, message: "line is empty", line: linenum)
                continue lineLoop
            }
            let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            
            if line.starts(with: "object-group network") {
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2] {
                    objectName = objectNameTemp
                }
                continue lineLoop
            }
            
            if line.starts(with: "network-object") {
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let term1 = words[safe: 1], let term2 = words[safe: 2], let objectName = objectName, let ipRange = IpRange(ip: term1, mask: term2, type: .asa) {
                    if var objectGroup = objectGroups[objectName] {
                        objectGroup.append(ipRange: ipRange)
                    } else {
                        let objectGroup = ObjectGroup(ipRange: ipRange)
                        objectGroups[objectName] = objectGroup
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "ip access-list extended") {
                objectName = nil
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let aclName = words[safe: 3] {
                    names.insert(aclName)
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found")
                    }
                }
                continue lineLoop
            }
            
            if let accessControlEntry = AccessControlEntry(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: self, errorDelegate: delegate) {
                objectName = nil
                accessControlEntries.append(accessControlEntry)
            }
        }
    }
    
    public func analyze(socket: Socket, errorDelegate: ErrorDelegate? = nil) -> AclAction {
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
                    errorDelegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: lineNumber)
                    //delegate?.report(severity: .result, message: "FIRST MATCH \(aclAction)", line: lineNumber)
                } else {
                    // later match in acl
                    errorDelegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: lineNumber)
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
}
extension AccessList: AclDelegate {
    func getObjectGroup(_ group: String) -> ObjectGroup? {
        if let objectGroup = self.objectGroups[group] {
            return objectGroup
        } else {
            return nil
        }
    }
    func foundName(_ name: String) {
        names.insert(name)
        if names.count > 1 {
            self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found")
        }
    }
}

