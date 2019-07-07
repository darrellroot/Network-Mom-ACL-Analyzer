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
    var objectGroupNetworks = [String:ObjectGroupNetwork]()
    var objectGroupProtocols = [String:ObjectGroupProtocol]()
    var objectGroupServices = [String:ObjectGroupService]()

    var count: Int {
        return accessControlEntries.count
    }
    
    enum ConfigurationMode {
        case objectGroupNetwork
        case objectGroupProtocol
        case objectGroupService
        case accessListExtended
        case accessControlEntry  // default
    }
    
    init(sourceText: String, deviceType: DeviceType, delegate: ErrorDelegate? = nil) {
        self.sourceText = sourceText
        self.delegate = delegate
        self.deviceType = deviceType
        var linenum = 0
        var configurationMode: ConfigurationMode = .accessControlEntry
        var objectName: String? = nil  //non-nil if we are in object-group mode
        
        lineLoop: for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            linenum = linenum + 1
            if line.isEmpty {
                //delegate?.report(severity: .notification, message: "line is empty", line: linenum)
                continue lineLoop
            }
            let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            
            if line.starts(with: "object-group network") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                        configurationMode = .objectGroupNetwork
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum)
                        configurationMode = .accessControlEntry
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "object-group service") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2], let type = words[safe: 3] {
                    guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum)
                        configurationMode = .accessControlEntry
                        objectName = nil
                        continue lineLoop
                    }
                    switch type {
                    case "tcp":
                        let objectGroupService = ObjectGroupService(type: .tcp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        objectName = objectNameTemp
                        continue lineLoop
                    case "udp":
                        let objectGroupService = ObjectGroupService(type: .udp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        objectName = objectNameTemp
                        continue lineLoop
                    case "tcp-udp":
                        let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        objectName = objectNameTemp
                        continue lineLoop
                    default:
                        delegate?.report(severity: .error, message: "Invalid object-group type \(type)", line: linenum)
                        configurationMode = .accessControlEntry
                        objectName = nil
                        continue lineLoop
                    }
                }
                continue lineLoop //should not get here but just in case
            }
            
            if line.starts(with: "object-group protocol") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupProtocols[objectNameTemp] = ObjectGroupProtocol()
                        configurationMode = .objectGroupProtocol
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group protocol \(objectNameTemp)", line: linenum)
                        configurationMode = .accessControlEntry
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "protocol-object") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if configurationMode != .objectGroupProtocol {
                    delegate?.report(severity: .error, message: "Unexpected protocol-object", line: linenum)
                    continue lineLoop
                }
                if let term1 = words[safe: 1], let objectName = objectName {
                    // get protocol number
                    var ipProtocol: UInt? = nil
                    if let protocolNumber = UInt(term1) {
                        if protocolNumber < 256 {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "IP protocol must be between 0 and 255 inclusive", line: linenum)
                            continue lineLoop
                        }
                    } else {
                        if let protocolNumber = term1.ipProtocol {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum)
                            continue lineLoop
                        }
                    }
                    if let ipProtocol = ipProtocol, let objectGroupProtocol = objectGroupProtocols[objectName] {
                        objectGroupProtocol.append(ipProtocol: ipProtocol)
                    }
                } else {
                    delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum)
                }
                continue lineLoop
            }
            
            if line.starts(with: "network-object") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if configurationMode != .objectGroupNetwork {
                    delegate?.report(severity: .error, message: "Unexpected network-object", line: linenum)
                    continue lineLoop
                }
                if let term1 = words[safe: 1], let term2 = words[safe: 2], let objectName = objectName, let ipRange = IpRange(ip: term1, mask: term2, type: .asa) {
                    if let objectGroupNetwork = objectGroupNetworks[objectName] {
                        objectGroupNetwork.append(ipRange: ipRange)
                    }
                continue lineLoop
                }
            }
            
            if line.starts(with: "ip access-list extended") {
                if deviceType == .asa {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid syntax for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                objectName = nil
                configurationMode = .accessListExtended
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let aclName = words[safe: 3] {
                    names.insert(aclName)
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found")
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "description") {
                if configurationMode == .objectGroupNetwork || configurationMode == .objectGroupService || configurationMode == .objectGroupProtocol {
                    continue lineLoop
                } else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum)
                    delegate?.report(severity: .warning, message: "Unexpected description", line: linenum)
                    continue lineLoop
                }
            }
            if line.starts(with: "port-object") {
                if deviceType == .ios {
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let portOperator = words[safe: 1] {
                    switch portOperator {
                    case "eq":
                        if let portNumber = words[safe: 2]?.port, let portRange = PortRange(minPort: portNumber, maxPort: portNumber), let objectName = objectName, let objectGroup = objectGroupServices[objectName] {
                            objectGroup.append(portRange: portRange)
                            continue lineLoop
                        } else {
                            continue lineLoop
                        }
                    case "range":
                        if let lowPort = words[safe: 2]?.port, let highPort = words[safe: 3]?.port, let portRange = PortRange(minPort: lowPort, maxPort: highPort), let objectName = objectName, let objectGroup = objectGroupServices[objectName] {
                            objectGroup.append(portRange: portRange)
                            continue lineLoop
                        } else {
                            continue lineLoop
                        }
                    default: // switch portOperator
                        continue lineLoop
                    }
                } else { // if let portOperator else
                    continue lineLoop
                }
            }
            
            if let accessControlEntry = AccessControlEntry(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: self, errorDelegate: delegate) {
                objectName = nil
                configurationMode = .accessControlEntry
                accessControlEntries.append(accessControlEntry)
            }
        }
    }
    
    public func analyze(socket: Socket, errorDelegate: ErrorDelegate? = nil) -> AclAction {
        var aclAction: AclAction? = nil
        for accessControlEntry in accessControlEntries {
            let aceAction = accessControlEntry.analyze(socket: socket)
            switch aceAction {
            case .neither:
                continue
            case .permit, .deny:
                if aclAction == nil {
                    // first match in acl
                    aclAction = aceAction
                    errorDelegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum)
                } else {
                    // later match in acl
                    errorDelegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum)
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
    func getObjectGroupNetwork(_ group: String) -> ObjectGroupNetwork? {
        if let objectGroupNetwork = self.objectGroupNetworks[group] {
            return objectGroupNetwork
        } else {
            return nil
        }
    }
    func getObjectGroupService(_ group: String) -> ObjectGroupService? {
        if let objectGroupService = self.objectGroupServices[group] {
            return objectGroupService
        } else {
            return nil
        }
    }
    func getObjectGroupProtocol(_ group: String) -> ObjectGroupProtocol? {
        if let objectGroupProtocol = self.objectGroupProtocols[group] {
            return objectGroupProtocol
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

