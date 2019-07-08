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
    var aclAction: AclAction = .neither  // neither means not initialized
    var ipVersion: IpVersion = .IPv4
    var listName: String?
    var ipProtocols: [UInt] = []  // 0 means ip
    var sourceIp: [IpRange] = []
    var sourcePort: [PortRange] = []  //empty list means no port restriction
    var destIp: [IpRange] = []
    var destPort: [PortRange] = []  // empty means no port restriction
    var established: Bool = false
    var line: String
    var linenum: Int
    var icmpMessages: [IcmpMessage] = []
    
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

    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate? = nil) {
        
        // These are temporary variables while parsing the ACE
        // If we successfully parse all of these
        // Then we can finish the initialization
        // at the end
        self.line = line
        self.linenum = linenum
        var tempAclAction: AclAction? = nil
        //var tempIpVersion: IpVersion? = .IPv4
        var tempListName: String? = nil
        //var tempIpProtocol: UInt? = nil
        var tempSourceOctet: UInt? = nil
        //var tempMinSourceIp: UInt? = nil
        //var tempMaxSourceIp: UInt? = nil
        var tempSourcePortOperator: PortOperator? = nil
        
        var tempRangeSourcePort: UInt? = nil
        //var tempSourcePort: [PortRange] = []
        //var tempMinSourcePort: UInt? = nil
        //var tempMaxSourcePort: UInt? = nil
        //var tempMinDestIp: UInt? = nil
        //var tempMaxDestIp: UInt? = nil
        //var tempDestPort: [PortRange] = []
        var tempDestOctet: UInt? = nil
        var tempDestPortOperator: PortOperator? = nil
        var tempRangeDestPort: UInt? = nil
        //var tempMinDestPort: UInt? = nil
        //var tempMaxDestPort: UInt? = nil
        var tempEstablished = false

        var linePosition: LinePosition = .beginning
        //var candidate = AccessControlEntryCandidate()
        
        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        if line.hasPrefix("ipv4 access-list") {
            let words = line.components(separatedBy: CharacterSet.whitespaces)
            if let name = words[safe: 2] {
                aclDelegate?.foundName(name)
            }
            return nil
        }
        let words = line.components(separatedBy: CharacterSet.whitespaces)
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = AclToken(deviceType: deviceType, string: word) else {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                return nil
            }
            switch linePosition {
            
            case .beginning:
                switch token {
                case .accessList:
                    linePosition = .accessList
                    continue wordLoop
                case .permit:
                    tempAclAction = .permit
                    linePosition = .action
                    continue wordLoop
                case .deny:
                    tempAclAction = .deny
                    linePosition = .action
                    continue wordLoop
                case .tcp, .ip, .udp, .icmp, .eq, .extended, .range, .gt, .lt, .ne, .established, .fourOctet, .name, .host, .log, .any:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid at \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .number: // IOS XR syntax with possible numbering
                    linePosition = .beginning
                    continue wordLoop
                case .remark:
                    linePosition = .remark
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .notification, message: "line has remark after \(linePosition)", line: linenum)
                    return nil
                case .comment:
                    // comment at beginning
                    return nil
                    //linePosition = .comment
                    //continue wordLoop
                }
            case .accessList:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq , .range, .remark, .comment, .gt, .lt, .ne, .extended, .established, .log, .fourOctet, .host, .any:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .number(let number):
                    tempListName = "\(number)"
                    linePosition = .listName
                    aclDelegate?.foundName("\(number)")
                case .name(let name):
                    tempListName = name
                    linePosition = .listName
                    aclDelegate?.foundName(name)
                }
            case .listName:
                switch token {
                    
                case .accessList, .tcp, .ip, .udp, .icmp, .eq, .range, .comment, .gt, .lt, .ne, .established, .log, .fourOctet, .number, .name, .host, .any:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .extended:
                    linePosition = .listName
                    if deviceType == .ios {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "ASA-syntax ace detected despite IOS device Type selected", line: linenum)
                        return nil
                    }
                case .permit:
                    tempAclAction = .permit
                    linePosition = .action
                case .deny:
                    tempAclAction = .deny
                    linePosition = .action
                case .remark:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .notification, message: "line has remark after \(linePosition)", line: linenum)
                    return nil
                }
            case .action:
                switch token {
                
                case .accessList, .permit, .deny, .eq, .range, .remark, .comment, .gt, .lt, .ne, .established, .extended, .log, .fourOctet, .name, .host, .any:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    guard deviceType == .asa else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "Invalid objectgroup as position \(linePosition) for device type \(deviceType)", line: linenum)
                        return nil
                    }
                    linePosition = .protocolObjectGroup
                case .tcp:
                    self.ipProtocols.append(6)
                    linePosition = .ipProtocol
                case .ip:
                    self.ipProtocols.append(0)
                    linePosition = .ipProtocol
                case .udp:
                    self.ipProtocols.append(17)
                    linePosition = .ipProtocol
                case .icmp:
                    self.ipProtocols.append(1)
                    linePosition = .ipProtocol
                case .number(let number):
                    if number > 255 || number < 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid ip protocol after \(linePosition)", line: linenum)
                        return nil
                    } else {
                        self.ipProtocols.append(number)
                        //tempIpProtocol = number
                        linePosition = .ipProtocol
                    }
                }
            case .protocolObjectGroup:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .objectGroup, .host, .any, .fourOctet(_), .range, .remark, .comment, .extended, .gt, .lt, .ne, .established, .log, .number:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .name(let objectName):
                    guard let protocolObjectGroup = aclDelegate?.getObjectGroupProtocol(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)")
                        return nil
                    }
                    self.ipProtocols = protocolObjectGroup.ipProtocols
                }
                linePosition = .ipProtocol
            case .ipProtocol:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .extended, .gt, .lt, .ne, .established, .log, .number, .name:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    linePosition = .sourceObjectGroup
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: UInt(UInt32.max))
                    self.sourceIp.append(ipRange)
                    //tempMinSourceIp = 0
                    //tempMaxSourceIp = UInt(UInt32.max)
                    linePosition = .sourceMask
                case .fourOctet(let number):
                    tempSourceOctet = number
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                }
            case .sourceIp:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number, .name:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let sourceMask):
                    let numSourceHosts: UInt
                    switch deviceType {
                    case .ios:
                        guard let numSourceHostsTemp = sourceMask.dontCareHosts else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(deviceType)", line: linenum)
                            return nil
                        }
                        numSourceHosts = numSourceHostsTemp
                    case .asa:
                        guard let numSourceHostsTemp = sourceMask.netmaskHosts else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(deviceType)", line: linenum)
                            return nil
                        }
                        numSourceHosts = numSourceHostsTemp
                    }
                    guard tempSourceOctet != nil else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    let remainder = tempSourceOctet! % numSourceHosts
                    if remainder > 0 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum)
                    }
                    let tempMinSourceIp = tempSourceOctet! - remainder
                    let tempMaxSourceIp = tempMinSourceIp + numSourceHosts - 1
                    let ipRange = IpRange(minIp: tempMinSourceIp, maxIp: tempMaxSourceIp)
                    self.sourceIp.append(ipRange)
                    linePosition = .sourceMask
                }
                
            case .sourceIpHost:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let ipNumber):
                    let ipRange = IpRange(minIp: ipNumber, maxIp: ipNumber)
                    self.sourceIp.append(ipRange)
                    //tempMinSourceIp = ipNumber
                    //tempMaxSourceIp = ipNumber
                case .name(_):
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) DNS resolution of hostnames is not supported by Network Mom", line: linenum)
                    return nil
                }
                linePosition = .sourceMask
            case .sourceObjectGroup:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number, .objectGroup, .fourOctet:
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                        return nil
                case .name(let objectName):
                    let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName)
                    if sourceObjectGroup == nil {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)")
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup!.ipRanges
                }
                linePosition = .sourceMask
            case .sourceMask:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .remark, .comment, .number, .name, .established, .log:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    linePosition = .destObjectGroup
                case .eq:
                    tempSourcePortOperator = .eq
                    linePosition = .sourcePortOperator
                case .range:
                    tempSourcePortOperator = .range
                    linePosition = .sourcePortOperator
                case .host:
                    linePosition = .destIpHost
                case .any:
                    let destIp = IpRange(minIp: 0, maxIp: UInt(UInt32.max))
                    self.destIp.append(destIp)
                    linePosition = .destMask
                case .gt:
                    tempSourcePortOperator = .gt
                    linePosition = .sourcePortOperator
                case .ne:
                    if deviceType == .ios {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) IOS does not support ne port operator", line: linenum)
                        return nil
                    }
                    tempSourcePortOperator = .ne
                    linePosition = .sourcePortOperator
                case .lt:
                    tempSourcePortOperator = .lt
                    linePosition = .sourcePortOperator
                case .fourOctet(let ipNumber):
                    tempDestOctet = ipNumber
                    linePosition = .destIp
                }
            case .sourcePortOperator:
                switch token {
                    
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                        return nil
                    }
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempSourcePortOperator {
                        
                    case .eq:
                        if let sourcePort = PortRange(minPort: port, maxPort: port) {
                            self.sourcePort.append(sourcePort)
                        } else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        }
                        //tempMinSourcePort = port
                        //tempMaxSourcePort = port
                        linePosition = .lastSourcePort
                    case .ne:
                        
                        switch port {
                        case 0:
                            let sourcePort = PortRange(minPort: 1, maxPort: 65535)!
                            self.sourcePort.append(sourcePort)
                        case 65535:
                            let sourcePort = PortRange(minPort: 0, maxPort: 65534)!
                            self.sourcePort.append(sourcePort)
                        case 1...65534:
                            guard let sourcePort1 = PortRange(minPort: 0, maxPort: port - 1), let sourcePort2 = PortRange(minPort: port + 1, maxPort: 65535) else  {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.sourcePort.append(sourcePort1)
                            self.sourcePort.append(sourcePort2)
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                            return nil
                        }
                    case .gt:
                        guard port < 65535 else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        guard let sourcePort = PortRange(minPort: port + 1, maxPort: 65535) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        self.sourcePort.append(sourcePort)
                        linePosition = .lastSourcePort
                    case .lt:
                        guard let sourcePort = PortRange(minPort: 0, maxPort: port - 1) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        self.sourcePort.append(sourcePort)
                        linePosition = .lastSourcePort
                    case .range:
                        tempRangeSourcePort = port
                        linePosition = .firstSourcePort
                    }
                    //end code snippet A
                case .name(let name):
                    var possiblePort: UInt?
                    for ipProtocol in self.ipProtocols {
                        switch ipProtocol {
                        case 6:
                            if let tempPort = name.tcpPort {
                                possiblePort = tempPort
                            }
                        case 17:
                            if let tempPort = name.udpPort {
                                possiblePort = tempPort
                            }
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                            return nil
                        }
                    }
                    guard let port = possiblePort else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid source port", line: linenum)
                        return nil
                    }
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempSourcePortOperator {
                        
                    case .eq:
                        guard let sourcePort = PortRange(minPort: port, maxPort: port) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                            return nil
                        }
                        self.sourcePort.append(sourcePort)
                        linePosition = .lastSourcePort
                    case .ne:
                        switch port {
                        case 0:
                            let sourcePort = PortRange(minPort: 1, maxPort: 65535)!
                            self.sourcePort.append(sourcePort)
                        case 65535:
                            let sourcePort = PortRange(minPort: 0, maxPort: 65534)!
                            self.sourcePort.append(sourcePort)
                        case 1...65534:
                            guard let sourcePort1 = PortRange(minPort: 0, maxPort: port - 1), let sourcePort2 = PortRange(minPort: port + 1, maxPort: 65535) else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.sourcePort.append(sourcePort1)
                            self.sourcePort.append(sourcePort2)
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                            return nil
                        }
                    case .gt:
                        guard let sourcePort = PortRange(minPort: port + 1, maxPort: 65535) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        self.sourcePort.append(sourcePort)
                        linePosition = .lastSourcePort
                    case .lt:
                        guard let sourcePort = PortRange(minPort: 0, maxPort: port - 1) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        self.sourcePort.append(sourcePort)
                        linePosition = .lastSourcePort
                    case .range:
                        tempRangeSourcePort = port
                        linePosition = .firstSourcePort
                    }
                    //end code snippet A
                }
            case .firstSourcePort:
                switch token {
                    
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid source port)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "Unexpected object-group at \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard let tempRangeSourcePort = tempRangeSourcePort else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    guard let sourcePort = PortRange(minPort: tempRangeSourcePort, maxPort: port) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    for ipProtocol in self.ipProtocols {
                        switch ipProtocol {
                        case 6:
                            if let tempPort = name.tcpPort {
                                possiblePort = tempPort
                            }
                        case 17:
                            if let tempPort = name.udpPort {
                                possiblePort = tempPort
                            }
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                            return nil
                        }
                    }
                    guard let port = possiblePort else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid source port)", line: linenum)
                        return nil
                    }
                    guard let tempRangeSourcePort = tempRangeSourcePort else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    guard let sourcePort = PortRange(minPort: tempRangeSourcePort, maxPort: port) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .gt, .lt, .ne, .established, .log, .number, .name:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    linePosition = .sourceObjectGroup
                case .host:
                    linePosition = .destIpHost
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: UInt(UInt32.max))
                    self.destIp.append(ipRange)
                    linePosition = .destMask
                case .fourOctet(let ipNumber):
                    tempDestOctet = ipNumber
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number, .name:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "Unexpected object-group at \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let destMask):
                    let numDestHosts: UInt
                    switch deviceType {
                    case .ios:
                        guard let numDestHostsTemp = destMask.dontCareHosts else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(deviceType)", line: linenum)
                            return nil
                        }
                        numDestHosts = numDestHostsTemp
                    case .asa:
                        guard let numDestHostsTemp = destMask.netmaskHosts else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(deviceType)", line: linenum)
                            return nil
                        }
                        numDestHosts = numDestHostsTemp
                    }
                    guard tempDestOctet != nil else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "error decoding destination ip", line: linenum)
                        return nil
                    }
                    let remainder = tempDestOctet! % numDestHosts
                    if remainder > 0 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum)
                    }
                    let tempMinDestIp = tempDestOctet! - remainder
                    let tempMaxDestIp = tempMinDestIp + numDestHosts - 1
                    let ipRange = IpRange(minIp: tempMinDestIp, maxIp: tempMaxDestIp)
                    self.destIp.append(ipRange)
                    linePosition = .destMask
                }

            case .destIpHost:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "Unexpected object-group at \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let ipNumber):
                    let ipRange = IpRange(minIp: ipNumber, maxIp: ipNumber)
                    self.destIp.append(ipRange)
                    //tempMinDestIp = ipNumber
                    //tempMaxDestIp = ipNumber
                case .name(_):
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) DNS resolution of hostnames is not supported", line: linenum)
                    return nil
                }
                linePosition = .destMask
            case .destObjectGroup:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .number, .objectGroup, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "Error decoding object group at \(linePosition)", line: linenum)
                    return nil
                case .name(let objectName):
                    // could be service object group for source port
                    // or could be dest object group
                    if let serviceObjectGroup = aclDelegate?.getObjectGroupService(objectName) {
                        guard self.sourcePort.count == 0 else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "Duplicate source port configuration")
                            return nil
                        }
                        self.sourcePort = serviceObjectGroup.portRanges
                        linePosition = .lastSourcePort
                    } else {
                        guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)")
                            return nil
                        }
                        self.destIp = destObjectGroup.ipRanges
                        linePosition = .destMask
                    }
                }
            case .destMask:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .remark, .comment, .host, .any, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    linePosition = .destObjectService
                case .name(let name):  // only valid for icmp here
                    guard self.ipProtocols.contains(1) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    if let icmpMessage = IcmpMessage(deviceType: deviceType, message: name) {
                            self.icmpMessages.append(icmpMessage)
                    } else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                case .number(let number):
                    guard self.ipProtocols.contains(1) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    guard let icmpMessage = IcmpMessage(type: number, code: nil) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    self.icmpMessages.append(icmpMessage)
                case .established:
                    guard deviceType == .ios else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning for stateless devices, not device type \(deviceType)", line: linenum)
                        return nil
                    }
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) established only has meaning for TCP protocol", line: linenum)
                        return nil
                    }
                    tempEstablished = true
                    linePosition = .end
                case .ne:
                    if deviceType == .ios {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) IOS does not support ne port operator", line: linenum)
                        return nil
                    }
                    tempDestPortOperator = .ne
                    linePosition = .destPortOperator
                case .eq:
                    tempDestPortOperator = .eq
                    linePosition = .destPortOperator
                case .range:
                    tempDestPortOperator = .range
                    linePosition = .destPortOperator
                case .gt:
                    tempDestPortOperator = .gt
                    linePosition = .destPortOperator
                case .lt:
                    tempDestPortOperator = .lt
                    linePosition = .destPortOperator
                case .log:
                    linePosition = .end
                }
            case .destObjectService:
                switch token {
                    case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .number, .objectGroup, .ne, .established, .log, .fourOctet:
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    case .name(let objectName):
                        // must be service object group for dest port
                        if let serviceObjectGroup = aclDelegate?.getObjectGroupService(objectName) {
                            guard self.destPort.count == 0 else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "Duplicate dest port configuration")
                                return nil
                            }
                            self.destPort = serviceObjectGroup.portRanges
                            linePosition = .lastDestPort
                    }
                }
            case .destPortOperator:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    //start code snippet B
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "destination port operator not found after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempDestPortOperator {
                        
                    case .eq:
                        guard let destPort = PortRange(minPort: port, maxPort: port) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        self.destPort.append(destPort)
                        linePosition = .lastDestPort
                    case .ne:
                        switch port {
                        case 0:
                            let destPort = PortRange(minPort: 1, maxPort: 65535)!
                            self.destPort.append(destPort)
                        case 65535:
                            let destPort = PortRange(minPort: 0, maxPort: 65534)!
                            self.destPort.append(destPort)
                        case 1...65534:
                            guard let destPort1 = PortRange(minPort: 0, maxPort: port - 1), let destPort2 = PortRange(minPort: port + 1, maxPort: 65535) else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "unexpected port error after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.destPort.append(destPort1)
                            self.destPort.append(destPort2)
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                            return nil
                        }
                        linePosition = .lastDestPort
                    case .gt:
                        guard let destPort = PortRange(minPort: port + 1, maxPort: 65535) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        self.destPort.append(destPort)
                        linePosition = .lastDestPort
                    case .lt:
                        guard let destPort = PortRange(minPort: 0, maxPort: port - 1) else {
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        self.destPort.append(destPort)
                        linePosition = .lastDestPort
                    case .range:
                        tempRangeDestPort = port
                        linePosition = .firstDestPort
                    }
                //end code snippet B
                case .name(let name):
                    var possiblePort: UInt?
                    for ipProtocol in self.ipProtocols {
                        switch ipProtocol {
                        case 6:
                            if let tempPort = name.tcpPort {
                                possiblePort = tempPort
                            }
                        case 17:
                            if let tempPort = name.udpPort {
                                possiblePort = tempPort
                            }
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                            return nil
                        }
                    }
                    guard let port = possiblePort else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    //start code snippet B
                    
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "destination port operator not found after \(linePosition)", line: linenum)
                        return nil
                    }

                    switch tempDestPortOperator {

                        case .eq:
                            guard let destPort = PortRange(minPort: port, maxPort: port) else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.destPort.append(destPort)
                            linePosition = .lastDestPort
                        case .ne:
                            switch port {
                            case 0:
                                let destPort = PortRange(minPort: 1, maxPort: 65535)!
                                self.destPort.append(destPort)
                            case 65535:
                                let destPort = PortRange(minPort: 0, maxPort: 65534)!
                                self.destPort.append(destPort)
                            case 1...65534:
                                guard let destPort1 = PortRange(minPort: 0, maxPort: port - 1), let destPort2 = PortRange(minPort: port + 1, maxPort: 65535) else {
                                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                    errorDelegate?.report(severity: .error, message: "unexpected destination port error after \(linePosition)", line: linenum)
                                    return nil
                                }
                                self.destPort.append(destPort1)
                                self.destPort.append(destPort2)
                            default:
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                                return nil
                            }
                            linePosition = .lastDestPort
                        case .gt:
                            guard let destPort = PortRange(minPort: port + 1, maxPort: 65535) else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.destPort.append(destPort)
                            linePosition = .lastDestPort
                        case .lt:
                            guard let destPort = PortRange(minPort: 0, maxPort: port - 1) else {
                                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                                errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                                return nil
                            }
                            self.destPort.append(destPort)
                            linePosition = .lastDestPort
                        case .range:
                            tempRangeDestPort = port
                            linePosition = .firstDestPort
                        }
                    //end code snippet B

                }
            case .firstDestPort:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard let tempRangeDestPort = tempRangeDestPort, let destPort = PortRange(minPort: tempRangeDestPort, maxPort: port) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let name):
                    var possiblePort: UInt?
                    for ipProtocol in self.ipProtocols {
                        switch ipProtocol {
                        case 6:
                            if let tempPort = name.tcpPort {
                                possiblePort = tempPort
                            }
                        case 17:
                            if let tempPort = name.udpPort {
                                possiblePort = tempPort
                            }
                        default:
                            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                            errorDelegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                            return nil
                        }
                    }
                    guard let port = possiblePort, let tempRangeDestPort = tempRangeDestPort, let destPort = PortRange(minPort: tempRangeDestPort, maxPort: port) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .accessList, .permit, .deny, .extended, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .gt, .lt, .ne, .number, .name, .host, .any, .fourOctet:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                    return nil
                case .objectGroup:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "ACL Analyzer does not support object-group at \(linePosition)", line: linenum)
                    return nil
                case .log:
                    linePosition = .log
                case .comment:
                    linePosition = .comment
                case .established:
                    guard deviceType == .ios else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning for stateless devices, not device type \(deviceType)", line: linenum)
                        return nil
                    }
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .error, message: "invalid after \(linePosition) established only has meaning for TCP protocol", line: linenum)
                        return nil
                    }
                    tempEstablished = true
                    linePosition = .end
                }

            case .log:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .extended, .objectGroup, .range, .host, .any, .remark, .gt, .lt, .ne, .established, .log, .fourOctet(_):
                    break
                case .comment:
                    linePosition = .comment
                case .number(let logLevel):
                    switch logLevel {
                    case (0...7):
                        break
                    default:
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .warning, message: "possibly invalid logging level after \(linePosition)", line: linenum)
                    }
                case .name(let logName):
                    switch logName {
                    case "interval":
                        linePosition = .logInterval
                    case "disable", "default":
                        linePosition = .log
                    default:
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .warning, message: "possibly invalid logging level after \(linePosition)", line: linenum)
                    }
                }
            case .logInterval:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .extended, .objectGroup, .range, .host, .any, .remark, .comment, .gt, .lt, .ne, .established, .log, .name(_),.fourOctet(_):
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .warning, message: "possibly invalid logging interval after \(linePosition)", line: linenum)
                    linePosition = .end
                case .number(let logLevel):
                    switch logLevel {
                    case (1...600):
                        linePosition = .log
                    default:
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                        errorDelegate?.report(severity: .warning, message: "possibly invalid logging interval after \(linePosition)", line: linenum)
                    }
                }
            case .end:
                switch token {
                case .log:
                    linePosition = .log
                case .comment:
                    linePosition = .comment
                default:
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                }
            case .comment:
                break // do nothing, we are in a comment
            case .remark:
                return nil
            }
        }
        
        guard tempAclAction != nil else {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
            errorDelegate?.report(severity: .error, message: "no acl action found", line: linenum)
            return nil
        }
        self.aclAction = tempAclAction!
        self.ipVersion = .IPv4
        self.listName = tempListName
        
        guard self.sourceIp.count > 0 else {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
            errorDelegate?.report(severity: .error, message: "source ip not found", line: linenum)
            return nil
        }

        guard self.destIp.count > 0 else {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
            errorDelegate?.report(severity: .error, message: "dest ip not found", line: linenum)
            return nil
        }
        
        self.established = tempEstablished

        guard self.ipProtocols.count > 0 else {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum)
            errorDelegate?.report(severity: .error, message: "no protocol found", line: linenum)
            return nil
        }
        for ipProtocol in ipProtocols {
            switch ipProtocol {
            case 6, 17:
                break
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                    errorDelegate?.report(severity: .error, message: "Only protocols tcp and udp support port numbers", line: linenum)
                    return nil
                }
            default:
                // should not get here
                errorDelegate?.report(severity: .linetext, message: line, line: linenum)
                errorDelegate?.report(severity: .error, message: "Unable to identify ip protocol", line: linenum)
            }
        }
    }
    func analyze(socket: Socket) -> AclAction {
        // check source ip
        var sourceIpMatch = false
        for sourceIpRange in self.sourceIp {
            if socket.sourceIp >= sourceIpRange.minIp && socket.sourceIp <= sourceIpRange.maxIp {
                sourceIpMatch = true
            }
        }
        var destIpMatch = false
        for destIpRange in self.destIp {
            if socket.destinationIp >= destIpRange.minIp && socket.destinationIp <= destIpRange.maxIp {
                destIpMatch = true
            }
        }
        if sourceIpMatch == false || destIpMatch == false {
            return .neither
        }
        // check ip protocol
        var protocolMatch = false
        for ipProtocol in self.ipProtocols {
            if ipProtocol == 0 {
                protocolMatch = true
                // since ips already match and protocol is any this is a match
                return self.aclAction
            }
            if socket.ipProtocol == ipProtocol {
                protocolMatch = true
            }
        }
        if protocolMatch == false {
            return .neither
        }

        /*if self.ipProtocol == 0 { // no need to check ports for any ip protocol once ips match
            return self.aclAction
        }*/
        // check ports if protocol udp or tcp
        if socket.ipProtocol == 17 || socket.ipProtocol == 6, let socketSourcePort = socket.sourcePort, let socketDestPort = socket.destinationPort {
            var sourcePortMatch = false
            if self.sourcePort.count == 0 {
                sourcePortMatch = true
            }
            for aceSourcePort in self.sourcePort {
                if aceSourcePort.contains(ipProtocol: socket.ipProtocol, port: socketSourcePort) {
                    sourcePortMatch = true
                }
                /*if socketSourcePort >= aceSourcePort.minPort && socketSourcePort <= aceSourcePort.maxPort {
                    sourcePortMatch = true
                }*/
            }
            var destPortMatch = false
            if self.destPort.count == 0 {
                destPortMatch = true
            }
            for aceDestPort in self.destPort {
                if aceDestPort.contains(ipProtocol: socket.ipProtocol, port: socketDestPort) {
                    destPortMatch = true
                }
                /*if socketDestPort >= aceDestPort.minPort && socketDestPort <= aceDestPort.maxPort {
                    destPortMatch = true
                }*/
            }
            if sourcePortMatch == false || destPortMatch == false {
                return .neither
            }
        }
        // check established flag if tcp and if ace requires established
        if socket.ipProtocol == 6 {
            if self.established == true {
                guard socket.established == true else {
                    return .neither
                }
            }
        }
        // at this point the acl is a match so we obey the action
        return self.aclAction
    }
}

extension AccessControlEntry: CustomStringConvertible {
    var description: String {
        var sourcePortString = ""
        for sourcePort in self.sourcePort {
            sourcePortString = sourcePortString + sourcePort.description + " "
        }
        var destPortString = ""
        for destPort in self.destPort {
            destPortString = destPortString + destPort.description + " "
        }
        
        var returnString = "\(aclAction) \(ipVersion) \(ipProtocols) \(sourceIp) source ports \(sourcePortString) to \(destIp) dest ports \(destPortString)"
        if self.established {
            returnString.append(" established\n")
        } else {
            returnString.append("\n")
        }
        return returnString
    }
}

