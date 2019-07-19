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
        case iosXrObjectGroupNetwork
        case iosXrObjectGroupService
        case nxosObjectGroupAddress
        case nxosObjectGroupPort
        case objectGroupProtocol
        case objectGroupService
        case accessListExtended
        case accessControlEntry  // default
    }
    
    init(sourceText: String, deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) {
        self.sourceText = sourceText.lowercased()
        self.delegate = delegate
        self.deviceType = deviceType
        var linenum = 0
        var lastSequenceSeen: UInt = 0  // used for making sure sequence numbers increase in the acl, each time we change configuration mode we reset this
        var configurationMode: ConfigurationMode = .accessControlEntry
        var objectName: String? = nil  //non-nil if we are in object-group mode
       

        lineLoop: for line in self.sourceText.components(separatedBy: NSCharacterSet.newlines) {
            
            linenum = linenum + 1
            
            func reportError() {
                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                delegate?.report(severity: .error, message: "line invalid, not included in analysis", line: linenum, delegateWindow: delegateWindow)
            }

            if line.isEmpty {
                continue lineLoop
            }
            let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            
            let words = line.split{ $0.isWhitespace }.map{ String($0)}

            if self.deviceType == .iosxr && words[safe: 0] == "object-group" && words[safe: 1] == "network" && words[safe: 2] == "ipv4", let objectNameTemp = words[safe: 3]  {
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                    configurationMode = .iosXrObjectGroupNetwork
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                } else {
                    reportError()
                    delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
            }
            
            if self.deviceType == .iosxr && words[safe: 0] == "object-group" && words[safe: 1] == "port", let objectNameTemp = words[safe: 2]  {
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupServices[objectNameTemp] = ObjectGroupService(type: .tcpAndUdp)
                    configurationMode = .iosXrObjectGroupService
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                } else {
                    delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
            }

            if words[safe: 0] == "object-group" && words[safe: 1] == "network" && deviceType == .asa {
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                        configurationMode = .objectGroupNetwork
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if words[safe: 0] == "object-group" && words[safe: 1] == "ip" && words[safe: 2] == "address" && deviceType == .nxos, let objectNameTemp = words[safe: 3] {
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                }
                self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                configurationMode = .nxosObjectGroupAddress
                lastSequenceSeen = 0
                objectName = objectNameTemp
                continue lineLoop
            }
            
            if words[safe: 0] == "object-group" && words[safe: 1] == "ip" && words[safe: 2] == "port" && deviceType == .nxos, let objectNameTemp = words[safe: 3] {
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                    continue lineLoop
                }
                let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                self.objectGroupServices[objectNameTemp] = objectGroupService
                configurationMode = .nxosObjectGroupPort
                lastSequenceSeen = 0
                objectName = objectNameTemp
                continue lineLoop
            }
            if deviceType == .iosxr && configurationMode == .iosXrObjectGroupNetwork, let objectName = objectName, let objectGroup = objectGroupNetworks[objectName] {
                if words[safe: 0] == "description" {
                    continue lineLoop
                }
                if words[safe: 0] == "host" {
                    guard let ipString = words[safe:1], let ipAddress = ipString.ipv4address else {
                        
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "", line: linenum, delegateWindow: delegateWindow)
                        continue lineLoop
                    }
                    let hostIpRange = IpRange(minIp: ipAddress, maxIp: ipAddress)
                    objectGroup.append(ipRange: hostIpRange)
                    continue lineLoop
                }
                if words[safe: 0] == "range", let firstIpString = words[safe: 1], let firstIp = firstIpString.ipv4address, let secondIpString = words[safe: 2], let secondIp = secondIpString.ipv4address, firstIp <= secondIp {
                    let ipRange = IpRange(minIp: firstIp, maxIp: secondIp)
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if let possibleIpString = words[safe: 0], let possibleNetmaskString = words[safe: 1], let ipRange = IpRange(ip: possibleIpString, netmask: possibleNetmaskString) {
                    if ipRange.bitAligned == false {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .warning, message: "Not aligned on bit boundary", line: linenum, delegateWindow: delegateWindow)
                    }
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if words[safe: 0] == "object-group", let possibleObjectName = words[safe: 1], let nestedObjectGroup = self.objectGroupNetworks[possibleObjectName] {
                    objectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                    continue lineLoop
                }
            }
            
            if deviceType == .nxos && configurationMode == .nxosObjectGroupPort {
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                // first word could be sequence number
                var localwords: [String]
                if let firstWord = words.first, let thisSequence = UInt(firstWord) {
                    localwords = Array(words.dropFirst())
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                } else {
                    localwords = words
                }

                if let localword = localwords.first, let token = NxAclToken(string: localword), let currentObjectName = objectName, let currentObjectGroup = objectGroupServices[currentObjectName] {
                    switch token {
                    case .action(_), .ipProtocol, .any, .host, .comment, .log, .addrgroup,.portgroup,.established, .fourOctet, .cidr, .number, .name,.unsupported:
                        break
                        //do nothing and proceed to ACE analysis
                    case .portOperator(let portOperator):
                        guard let firstPortString = localwords[safe: 1], let firstPort = UInt(firstPortString) ?? firstPortString.nxosTcpPort ?? firstPortString.nxosUdpPort, firstPort >= 0, firstPort <= MAXPORT else {
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
                            if let secondPortString = localwords[safe: 2], let secondPort = UInt(secondPortString) ?? secondPortString.nxosTcpPort ?? secondPortString.nxosUdpPort, secondPort >= 0, secondPort <= MAXPORT, let portRange = PortRange(minPort: firstPort, maxPort: secondPort) {
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
                // first word could be sequence number, drop it and process the rest
                var localwords = words
                if let firstword = localwords[safe: 0], let thisSequence = UInt(firstword) {
                    localwords.removeFirst()
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                }
                if let word1 = localwords.first, let token = NxAclToken(string: word1), let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName] {
                
                    switch token {
                        
                    case .action(_),.ipProtocol, .any, .portOperator, .comment, .log, .addrgroup,.portgroup,.established, .number, .name, .unsupported:
                        break
                        //do nothing and continue, we might be done with object group
                    case .host:
                        guard let word2 = localwords[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(hostIp) = token2, hostIp >= 0, hostIp <= MAXIP else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
                            objectName = nil
                            continue lineLoop
                        }
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp)
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
                    case .fourOctet(let network):
                        guard let word2 = localwords[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(dontCare) = token2, dontCare >= 0, dontCare <= MAXIP, let ipRange = IpRange(ipv4: network, dontCare: dontCare) else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
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
            
            //if line.starts(with: "object-group service") {
            if words[safe: 0] == "object-group" && words[safe: 1] == "service" {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                //let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let objectNameTemp = words[safe: 2], let type = words[safe: 3] {
                    guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                    }
                    switch type {
                    case "tcp":
                        let objectGroupService = ObjectGroupService(type: .tcp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        continue lineLoop
                    case "udp":
                        let objectGroupService = ObjectGroupService(type: .udp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        continue lineLoop
                    case "tcp-udp":
                        let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        continue lineLoop
                    default:
                        delegate?.report(severity: .error, message: "Invalid object-group type \(type)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                    }
                }
                continue lineLoop //should not get here but just in case
            }
            
            if words[safe: 0] == "object-group" && words[safe: 1] == "protocol" {
            //if line.starts(with: "object-group protocol") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                //let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupProtocols[objectNameTemp] = ObjectGroupProtocol()
                        configurationMode = .objectGroupProtocol
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group protocol \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
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
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
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
                case .accessListExtended, .accessControlEntry, .nxosObjectGroupPort, .nxosObjectGroupAddress, .iosXrObjectGroupNetwork, .iosXrObjectGroupService:
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "unexpected group-object", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if words[safe: 0] == "protocol-object" {
            //if line.starts(with: "protocol-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
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
            if words[safe: 0] == "network-object" {
            //if line.starts(with: "network-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
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
            if words[safe: 0] == "ip" && words[safe: 1] == "access-list" && words[safe: 2] == "extended" {
            //if line.starts(with: "ip access-list extended") {
                guard deviceType == .ios else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "invalid syntax for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let aclName = words[safe: 3] {
                    names.insert(aclName)
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            if words[safe: 0] == "ip" && words[safe: 1] == "access-list" {
            //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "invalid syntax for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    names.insert(String(aclName))
                    if names.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(names) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            if words[safe: 0] == "statistics" && words[safe: 1] == "per-entry" {
            //if line.starts(with: "statistics per-entry") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "statistics per entry not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                continue lineLoop
            }
            if words[safe: 0] == "fragments" && (words[safe: 1] == "permit-all" || words[safe: 1] == "deny-all") {
            //if line.starts(with: "fragments permit-all") || line.starts(with: "fragments deny-all") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "statistics per entry not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                delegate?.report(severity: .warning, message: "Fragments line not considered in ACL analysis", line: linenum, delegateWindow: delegateWindow)
                continue lineLoop
            }

            if words[safe: 0] == "description" {
            //if line.starts(with: "description") {
                if configurationMode == .objectGroupNetwork || configurationMode == .objectGroupService || configurationMode == .objectGroupProtocol {
                    continue lineLoop
                } else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "Unexpected description", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if words[safe: 0] == "port-object" {
            //if line.starts(with: "port-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
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
                if let thisSequence = accessControlEntry.sequence {
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                }
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

