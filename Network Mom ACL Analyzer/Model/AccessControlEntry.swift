//
//  AccessControlEntry.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

struct AccessControlEntry {
    let aclAction: AclAction
    let ipVersion: IpVersion
    let listName: String?
    let ipProtocol: UInt8
    let leastSourceIp: UInt
    let maxSourceIp: UInt
    let leastDestIp: UInt
    let maxDestIp: UInt
    let leastDestPort: UInt?
    var maxDestPort: UInt?
    let line: String
    
    func findAction(word: String) -> AclAction? {
        switch word {
        case "deny":
            return .deny
        case "permit":
            return .permit
        default:
            return nil
        }
    }

    init?(line: String, type: MaskType) {
        
        // These are temporary variables while parsing the ACE
        // If we successfully parse all of these
        // Then we can finish the initialization
        // at the end
        var aclAction: AclAction? = nil
        var ipVersion: IpVersion? = .IPv4
        var listName: String? = nil
        var ipProtocol: UInt8? = nil
        var leastSourceIp: UInt? = nil
        var maxSourceIp: UInt? = nil
        var leastDestIp: UInt? = nil
        var maxDestIp: UInt? = nil
        var destPortOperator: PortOperator? = nil
        var leastDestPort: UInt? = nil
        var maxDestPort: UInt? = nil

        var linePosition: LinePosition = .accessList
        //var candidate = AccessControlEntryCandidate()
        
        let words = line.components(separatedBy: NSCharacterSet.whitespaces)
        if words.count < 2 {
            return nil
        }

        wordLoop: for word in words {
            if word.first == "!" {
                return nil
            }
            switch linePosition {
                
            case .accessList:
                if word == "access-list" {
                    linePosition = .listName
                    continue wordLoop
                } else {
                    linePosition = .action
                    switch word {
                    case "deny":
                        aclAction = .deny
                    case "permit":
                        aclAction = .permit
                    default:
                        debugPrint("line \(line) invalid at aclAction")
                        return nil
                    }
                    linePosition = .ipProtocol
                }
            case .listName:
                listName = word
                linePosition = .action
            case .action:
                switch word {
                case "deny":
                    aclAction = .deny
                case "permit":
                    aclAction = .permit
                default:
                    debugPrint("line \(line) invalid at aclAction")
                    return nil
                }
                linePosition = .ipProtocol
                
            case .ipProtocol:
                switch word {
                case "tcp":
                    ipProtocol = 6
                case "udp":
                    ipProtocol = 17
                case "ip":
                    ipProtocol = 0
                default:
                    debugPrint("line \(line) invalid at ipProtocol")
                    return nil
                }
                linePosition = .sourceIp
            case .sourceIp:
                if word == "any" {
                    leastSourceIp = 0
                    maxSourceIp = UInt(UInt32.max)
                    linePosition = .destIp
                    continue wordLoop
                }
                if word == "host" {
                    linePosition = .sourceIpHost
                    continue wordLoop
                }
                guard let _ = IPv4Address(word) else {
                    debugPrint("line \(line) invalid at sourceIp")
                    return nil
                }
                leastSourceIp = word.ipv4address
                guard leastSourceIp != nil else {
                    debugPrint("line \(line) invalid at sourceIp")
                    return nil
                }
                linePosition = .sourceMask
            case .sourceIpHost:
                leastSourceIp = word.ipv4address
                guard leastSourceIp != nil else {
                    debugPrint("line \(line) invalid at sourceIpHost")
                    return nil
                }
                maxSourceIp = leastSourceIp
                linePosition = .destIp
            case .sourceMask:
                guard let sourceMask = word.ipv4address else {
                    debugPrint("line \(line) invalid at sourceMask")
                    return nil
                }
                let numSourceHosts: UInt
                
                switch type {
                case .dontCareBit:
                    guard let numSourceHostsTemp = sourceMask.dontCareHosts else {
                        debugPrint("line \(line) invalid at sourceMask acl type \(type)")
                        return nil
                    }
                    numSourceHosts = numSourceHostsTemp
                case .netmask:
                    guard let numSourceHostsTemp = sourceMask.netmaskHosts else {
                        debugPrint("line \(line) invalid at sourceMask acl type \(type)")
                        return nil
                    }
                    numSourceHosts = numSourceHostsTemp
                case .either:
                    debugPrint("line \(line) unknown acl type \(type)")
                    return nil
                }
                guard leastSourceIp != nil else {
                    debugPrint(" line \(line) unable to find leastSourceIp at sourceMask")
                    return nil
                }
                let remainder = leastSourceIp! % numSourceHosts
                if remainder > 0 {
                    debugPrint("warning line \(line) destination IP not on netmask or bit boundary\n")
                }
                leastSourceIp = leastSourceIp! - remainder
                maxSourceIp = leastSourceIp! + numSourceHosts - 1
                linePosition = .destIp
            case .destIp:
                if word == "any" {
                    leastDestIp = 0
                    maxDestIp = UInt(UInt32.max)
                    linePosition = .destPortQualifier
                    continue wordLoop
                }
                if word == "host" {
                    linePosition = .destIpHost
                    continue wordLoop
                }
                guard let _ = IPv4Address(word) else {
                    debugPrint("line \(line) invalid at destIp")
                    return nil
                }
                leastDestIp = word.ipv4address
                guard leastDestIp != nil else {
                    debugPrint("line \(line) invalid at destIp")
                    return nil
                }
                linePosition = .destMask
                
            case .destIpHost:
                leastDestIp = word.ipv4address
                guard leastDestIp != nil else {
                    debugPrint("line \(line) invalid at destIpHost")
                    return nil
                }
                maxDestIp = leastDestIp
                linePosition = .destPortQualifier
            case .destMask:
                guard let destMask = word.ipv4address else {
                    debugPrint("line \(line) invalid at destMask")
                    return nil
                }
                let numDestHosts: UInt
                switch type {
                    
                case .dontCareBit:
                    guard let numDestHostsTemp = destMask.dontCareHosts else {
                        debugPrint("line \(line) invalid at destMask acl type \(type)")
                        return nil
                    }
                    numDestHosts = numDestHostsTemp
                case .netmask:
                    guard let numDestHostsTemp = destMask.netmaskHosts else {
                        debugPrint("line \(line) invalid at destMask acl type \(type)")
                        return nil
                    }
                    numDestHosts = numDestHostsTemp
                case .either:
                    debugPrint("line \(line) unknown acl type \(type) at destMask")
                    return nil
                }
                guard leastDestIp != nil else {
                    debugPrint(" line \(line) unable to find leastDestIp at destMask")
                    return nil
                }
                let remainder = leastDestIp! % numDestHosts
                if remainder > 0 {
                    debugPrint("warning line \(line) destination IP not on netmask or bit boundary\n")
                }
                leastDestIp = leastDestIp! - remainder
                maxDestIp = leastDestIp! + numDestHosts - 1
                linePosition = .destPortQualifier
            case .destPortQualifier:
                switch word {
                case "eq":
                    destPortOperator = .eq
                    linePosition = .firstDestPort
                case "gt":
                    destPortOperator = .gt
                    linePosition = .firstDestPort
                case "lt":
                    destPortOperator = .lt
                    linePosition = .firstDestPort
                case "range":
                    destPortOperator = .range
                    linePosition = .firstDestPort
                case "log":  // nothing to analyze for log
                    linePosition = .end
                default:
                    debugPrint("line \(line) invalid at destinationPortQualifier")
                    return nil
                }
            case .firstDestPort:
                guard let firstDestPort32 = UInt32(word) else {
                    debugPrint("line \(line) invalid at firstPort")
                    return nil
                }
                let firstDestPort = UInt(firstDestPort32)
                guard let destPortOperator = destPortOperator else {
                    debugPrint("line \(line) invalid at firstDestPort, destPortOperator is nil")
                    return nil
                }
                switch destPortOperator {
                case .eq:
                    leastDestPort = firstDestPort
                    maxDestPort = firstDestPort
                    linePosition = .end
                case .gt:
                    if firstDestPort == 65535 {
                        debugPrint("line \(line) invalid at firstDestPort, cannot be gt 65535")
                        return nil
                    } else {
                        leastDestPort = firstDestPort + 1
                        maxDestPort = 65535
                        linePosition = .end
                    }
                case .lt:
                    if firstDestPort == 0 {
                        debugPrint("line \(line) invalid at firstDestPort, cannot be lt 0")
                        return nil
                    } else {
                        leastDestPort = 0
                        maxDestPort = firstDestPort - 1
                        linePosition = .end
                    }
                case .range:
                    leastDestPort = firstDestPort
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                guard let destPortOperator = destPortOperator else {
                    debugPrint("line \(line) invalid at firstDestPort, destPortOperator is nil")
                    return nil
                }

                switch destPortOperator {
                case .eq, .gt, .lt:
                    debugPrint("line \(line) invalid at lastDestPort, unknown state error")
                    return nil
                case .range:
                    guard let lastDestPort32 = UInt32(word) else {
                        debugPrint("line \(line) invalid at lastDestPort")
                        return nil
                    }
                    let lastDestPort = UInt(lastDestPort32)
                    guard let leastDestPort = leastDestPort else {
                        debugPrint("line \(line) invalid at lastDestPort, no leastDestPort found in range")
                        return nil
                    }
                    guard lastDestPort > leastDestPort else {
                        debugPrint("line \(line) invalid at range, \(lastDestPort) should be larger than \(leastDestPort)")
                        return nil
                    }
                    maxDestPort = lastDestPort
                }
            case .end:
                switch word {
                case "log":
                    break  // do nothing
                default:
                    debugPrint("line \(line) invalid at end")
                    return nil
                }
            }
        }
        guard let tempAclAction = aclAction else {
            return nil
        }
        self.aclAction = tempAclAction
        
        guard let tempIpVersion = ipVersion else {
            return nil
        }
        self.ipVersion = tempIpVersion
        
        self.listName = listName
        
        guard let tempIpProtocol = ipProtocol else {
            return nil
        }
        self.ipProtocol = tempIpProtocol
        
        guard let tempLeastSourceIp = leastSourceIp else {
            return nil
        }
        self.leastSourceIp = tempLeastSourceIp
        
        guard let tempMaxSourceIp = maxSourceIp else {
            return nil
        }
        self.maxSourceIp = tempMaxSourceIp
        
        guard let tempLeastDestIp = leastDestIp else {
            return nil
        }
        self.leastDestIp = tempLeastDestIp
        
        guard let tempMaxDestIp = maxDestIp else {
            return nil
        }
        self.maxDestIp = tempMaxDestIp

        // either both ports must be nil or non-nil
        if leastDestPort == nil && maxDestPort != nil {
            return nil
        }
        if leastDestPort != nil && maxDestPort == nil {
            return nil
        }
        self.leastDestPort = leastDestPort
        self.maxDestPort = maxDestPort
        
        self.line = line
        
        debugPrint(self)
    }
}

extension AccessControlEntry: CustomStringConvertible {
    var description: String {
        return "\(aclAction) \(ipVersion) \(ipProtocol.ipProto) \(leastSourceIp.ipv4) through \(maxSourceIp.ipv4) to \(leastDestIp.ipv4) through \(maxDestIp.ipv4) ports \(leastDestPort) through \(maxDestPort)\n"
    }
}

