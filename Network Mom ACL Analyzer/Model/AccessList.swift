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
    
    let MAXIP = UInt(UInt32.max)
    let MAXPORT = UInt(UInt16.max)

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
        case nxosObjectGroupAddress
        case nxosObjectGroupPort
        case objectGroupProtocol
        case objectGroupService
        case accessListExtended
        case accessControlEntry  // default
    }
    
    init(sourceText: String, deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) {
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
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                        configurationMode = .objectGroupNetwork
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "object-group ip address") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group ip address not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    objectName = nil
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                guard let objectNameTemp = words[safe: 3] else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "invalid object-group configuraiton for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    objectName = nil
                    continue lineLoop
                }
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        objectName = nil
                        continue lineLoop
                }
                self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                configurationMode = .nxosObjectGroupAddress
                objectName = objectNameTemp
                continue lineLoop
            }
            
            if line.starts(with: "object-group ip port") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group ip port not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    objectName = nil
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                guard let objectNameTemp = words[safe: 3] else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "Invalid object-group configuration", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    objectName = nil
                    continue lineLoop
                }
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    objectName = nil
                    continue lineLoop
                }
                let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                self.objectGroupServices[objectNameTemp] = objectGroupService
                configurationMode = .nxosObjectGroupPort
                objectName = objectNameTemp
                continue lineLoop
            }
            
            if deviceType == .nxos && configurationMode == .nxosObjectGroupPort {
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let word = words.first, let token = NxAclToken(string: word), let currentObjectName = objectName, let currentObjectGroup = objectGroupServices[currentObjectName] {
                    switch token {
                        
                    case .action(_), .ipProtocol, .any, .host, .comment, .log, .addrgroup,.portgroup,.established, .fourOctet, .cidr, .number, .name:
                        break
                        //do nothing and proceed to ACE analysis
                    case .portOperator(let portOperator):
                        guard let firstPortString = words[safe: 1], let firstPort = UInt(firstPortString) ?? firstPortString.nxosTcpPort ?? firstPortString.nxosUdpPort, firstPort >= 0, firstPort <= MAXPORT else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        switch portOperator {
                        case .eq:
                            if let portRange = PortRange(minPort: firstPort, maxPort: firstPort) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .gt:
                            if let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .lt:
                            if let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .ne:
                            if let portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1) {
                                currentObjectGroup.append(portRange: portRange1)
                            }
                            if let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) {
                                currentObjectGroup.append(portRange: portRange2)
                            }
                            continue lineLoop
                        case .range:
                            if let secondPortString = words[safe: 2], let secondPort = UInt(secondPortString) ?? secondPortString.nxosTcpPort ?? secondPortString.nxosUdpPort, secondPort >= 0, secondPort <= MAXPORT, let portRange = PortRange(minPort: firstPort, maxPort: secondPort) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        }
                    }
                }
            }
            
            if deviceType == .nxos && configurationMode == .nxosObjectGroupAddress {
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let word = words.first, let token = NxAclToken(string: word), let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName] {
                
                    switch token {
                        
                    case .action(_),.ipProtocol, .any, .portOperator, .comment, .log, .addrgroup,.portgroup,.established, .number, .name:
                        break
                        //do nothing and continue, we might be done with object group
                    case .host:
                        guard let word2 = words[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(hostIp) = token2, hostIp >= 0, hostIp <= MAXIP else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            objectName = nil
                            continue lineLoop
                        }
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp)
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
                    case .fourOctet(let network):
                        guard let word2 = words[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(dontCare) = token2, dontCare >= 0, dontCare <= MAXIP, let ipRange = IpRange(ipv4: network, dontCare: dontCare) else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            objectName = nil
                            continue lineLoop
                        }
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
                    case .cidr(let cidr):
                        currentObjectGroup.append(ipRange: cidr)
                        continue lineLoop
                    }
                }
            }
            
            if line.starts(with: "object-group service") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2], let type = words[safe: 3] {
                    guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
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
                        delegate?.report(severity: .error, message: "Invalid object-group type \(type)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        objectName = nil
                        continue lineLoop
                    }
                }
                continue lineLoop //should not get here but just in case
            }
            
            if line.starts(with: "object-group protocol") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupProtocols[objectNameTemp] = ObjectGroupProtocol()
                        configurationMode = .objectGroupProtocol
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group protocol \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "group-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                switch configurationMode {
                    
                case .objectGroupNetwork:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupNetworks[nestedObjectName] {
                        currentObjectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                        continue lineLoop
                    }
                case .objectGroupProtocol:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupProtocols[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupProtocols[nestedObjectName] {
                        currentObjectGroup.ipProtocols.append(contentsOf: nestedObjectGroup.ipProtocols)
                        continue lineLoop
                    }
                case .objectGroupService:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupServices[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupServices[nestedObjectName] {
                        if currentObjectGroup.type == nestedObjectGroup.type {
                            currentObjectGroup.portRanges.append(contentsOf: nestedObjectGroup.portRanges)
                        } else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "nested service object-groups must be the same type", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        continue lineLoop
                    }
                case .accessListExtended, .accessControlEntry, .nxosObjectGroupPort, .nxosObjectGroupAddress:
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "unexpected group-object", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if line.starts(with: "protocol-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if configurationMode != .objectGroupProtocol {
                    delegate?.report(severity: .error, message: "Unexpected protocol-object", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                if let term1 = words[safe: 1], let objectName = objectName {
                    // get protocol number
                    var ipProtocol: UInt? = nil
                    if let protocolNumber = UInt(term1) {
                        if protocolNumber < 256 {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "IP protocol must be between 0 and 255 inclusive", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                    } else {
                        if let protocolNumber = term1.ipProtocol {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                    }
                    if let ipProtocol = ipProtocol, let objectGroupProtocol = objectGroupProtocols[objectName] {
                        objectGroupProtocol.append(ipProtocol: ipProtocol)
                    }
                } else {
                    delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum, delegateWindow: delegateWindow)
                }
                continue lineLoop
            }
            
            if line.starts(with: "network-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if configurationMode != .objectGroupNetwork {
                    delegate?.report(severity: .error, message: "Unexpected network-object", line: linenum, delegateWindow: delegateWindow)
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
                guard deviceType == .ios else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "invalid syntax for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                objectName = nil
                configurationMode = .accessListExtended
                let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                if let aclName = words[safe: 3] {
                    names.insert(aclName)
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "invalid syntax for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                objectName = nil
                configurationMode = .accessListExtended
                let words = line.split(separator: " ")
                if let aclName = words[safe: 2] {
                    names.insert(String(aclName))
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            if line.starts(with: "statistics per entry") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "statistics per entry not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                continue lineLoop
            }
            if line.starts(with: "description") {
                if configurationMode == .objectGroupNetwork || configurationMode == .objectGroupService || configurationMode == .objectGroupProtocol {
                    continue lineLoop
                } else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "Unexpected description", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if line.starts(with: "port-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
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
            //debugPrint("starting timer")
            let timer = Timer(timeInterval: 1.0, repeats: false) { timer in
                //debugPrint("timer fired")
                self.delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                self.delegate?.report(severity: .error, message: "line took more than 1 second to parse, please email this line to feedback@networkmom.net", line: linenum, delegateWindow: delegateWindow)
            }
            RunLoop.main.add(timer, forMode: .common)
            
            if let accessControlEntry = AccessControlEntry(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: self, errorDelegate: delegate, delegateWindow: delegateWindow) {
                objectName = nil
                configurationMode = .accessControlEntry
                accessControlEntries.append(accessControlEntry)
            }
            timer.invalidate()
        }
    }
    
    public func analyze(socket: Socket, errorDelegate: ErrorDelegate? = nil, delegateWindow: DelegateWindow? = nil) -> AclAction {
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
                    errorDelegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                } else {
                    // later match in acl
                    errorDelegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                }
            }
        }
        guard let finalAclAction = aclAction else {
            // no match found, implicit deny
            delegate?.report(severity: .result, message: "No Match Found, implicit \(AclAction.deny)", delegateWindow: delegateWindow)
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

    func foundName(_ name: String, delegateWindow: DelegateWindow? = nil) {
        names.insert(name)
        if names.count > 1 {
            self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found", delegateWindow: delegateWindow)
        }
    }
}

