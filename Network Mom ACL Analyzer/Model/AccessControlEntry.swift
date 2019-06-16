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
    var aclAction: AclAction
    var ipVersion: IpVersion
    var listName: String?
    var ipProtocol: UInt  // 0 means ip
    var minSourceIp: UInt
    var maxSourceIp: UInt
    var minSourcePort: UInt?
    var maxSourcePort: UInt?
    var minDestIp: UInt
    var maxDestIp: UInt
    var minDestPort: UInt?
    var maxDestPort: UInt?
    var established: Bool
    var line: String
    var icmpMessage: IcmpMessage?
    
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

    init?(line: String, type: MaskType, linenum: Int, delegate: AclErrorDelegate? = nil) {
        
        // These are temporary variables while parsing the ACE
        // If we successfully parse all of these
        // Then we can finish the initialization
        // at the end
        var tempAclAction: AclAction? = nil
        var tempIpVersion: IpVersion? = .IPv4
        var tempListName: String? = nil
        var tempIpProtocol: UInt? = nil
        var tempMinSourceIp: UInt? = nil
        var tempMaxSourceIp: UInt? = nil
        var tempSourcePortOperator: PortOperator? = nil
        var tempMinSourcePort: UInt? = nil
        var tempMaxSourcePort: UInt? = nil
        var tempMinDestIp: UInt? = nil
        var tempMaxDestIp: UInt? = nil
        var tempDestPortOperator: PortOperator? = nil
        var tempMinDestPort: UInt? = nil
        var tempMaxDestPort: UInt? = nil
        var tempEstablished = false

        var linePosition: LinePosition = .beginning
        //var candidate = AccessControlEntryCandidate()
        
        let words = line.components(separatedBy: NSCharacterSet.whitespaces)
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = AclToken(string: word) else {
                delegate?.report(severity: .linetext, message: line, line: linenum)
                delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
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
                case .tcp, .ip, .udp, .icmp, .eq, .range, .gt, .lt, .established, .fourOctet, .number, .name, .host, .log, .any:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid at \(linePosition)", line: linenum)
                    return nil
                case .remark:
                    linePosition = .remark
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .notification, message: "line has remark after \(linePosition)", line: linenum)
                    return nil
                case .comment:
                    // comment at beginning
                    return nil
                    //linePosition = .comment
                    //continue wordLoop
                }
            case .accessList:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq , .range, .remark, .comment, .gt, .lt, .established, .log, .fourOctet, .host, .any:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil

                case .number(let number):
                    tempListName = "\(number)"
                    linePosition = .listName
                case .name(let name):
                    tempListName = name
                    linePosition = .listName
                }
            case .listName:
                switch token {
                    
                case .accessList, .tcp, .ip, .udp, .icmp, .eq, .range, .comment, .gt, .lt, .established, .log, .fourOctet, .number, .name, .host, .any:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .permit:
                    tempAclAction = .permit
                    linePosition = .action
                case .deny:
                    tempAclAction = .deny
                    linePosition = .action
                case .remark:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .notification, message: "line has remark after \(linePosition)", line: linenum)
                    return nil
                }
            case .action:
                switch token {
                
                case .accessList, .permit, .deny, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .fourOctet, .name, .host, .any:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil

                case .tcp:
                    tempIpProtocol = 6
                    linePosition = .ipProtocol
                case .ip:
                    tempIpProtocol = 0
                    linePosition = .ipProtocol
                case .udp:
                    tempIpProtocol = 17
                    linePosition = .ipProtocol
                case .icmp:
                    tempIpProtocol = 1
                    linePosition = .ipProtocol
                case .number(let number):
                    if number > 255 || number < 1 {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid ip protocol after \(linePosition)", line: linenum)
                        return nil
                    } else {
                        tempIpProtocol = number
                        linePosition = .ipProtocol
                    }
                }
            case .ipProtocol:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .any:
                    tempMinSourceIp = 0
                    tempMaxSourceIp = UInt(UInt32.max)
                    linePosition = .sourceMask
                case .fourOctet(let number):
                    tempMinSourceIp = number
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                }
            case .sourceIp:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let sourceMask):
                    let numSourceHosts: UInt
                    switch type {
                    case .dontCareBit:
                        guard let numSourceHostsTemp = sourceMask.dontCareHosts else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(type)", line: linenum)
                            return nil
                        }
                        numSourceHosts = numSourceHostsTemp
                    case .netmask:
                        guard let numSourceHostsTemp = sourceMask.netmaskHosts else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(type)", line: linenum)
                            return nil
                        }
                        numSourceHosts = numSourceHostsTemp
                    case .either:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .warning, message: "unknown acl type", line: linenum)
                        return nil
                    }
                    guard tempMinSourceIp != nil else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    let remainder = tempMinSourceIp! % numSourceHosts
                    if remainder > 0 {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum)
                    }
                    tempMinSourceIp = tempMinSourceIp! - remainder
                    tempMaxSourceIp = tempMinSourceIp! + numSourceHosts - 1
                    
                    linePosition = .sourceMask
                }
                
            case .sourceIpHost:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let ipNumber):
                    tempMinSourceIp = ipNumber
                    tempMaxSourceIp = ipNumber
                case .name(_):
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition) DNS resolution of hostnames is not supported by Network Mom", line: linenum)
                    return nil
                }
                linePosition = .sourceMask
            case .sourceMask:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .remark, .comment, .number, .name, .established, .log:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .eq:
                    tempSourcePortOperator = .eq
                    linePosition = .sourcePortOperator
                case .range:
                    tempSourcePortOperator = .range
                    linePosition = .sourcePortOperator
                case .host:
                    linePosition = .destIpHost
                case .any:
                    tempMinDestIp = 0
                    tempMaxDestIp = UInt(UInt32.max)
                    linePosition = .destMask
                case .gt:
                    tempSourcePortOperator = .gt
                    linePosition = .sourcePortOperator
                case .lt:
                    tempSourcePortOperator = .lt
                    linePosition = .sourcePortOperator
                case .fourOctet(let ipNumber):
                    tempMinDestIp = ipNumber
                    linePosition = .destIp
                }
            case .sourcePortOperator:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                        return nil
                    }
                    /*guard port >= 0 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                        return nil
                    }*/
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempSourcePortOperator {
                        
                    case .eq:
                        tempMinSourcePort = port
                        tempMaxSourcePort = port
                        linePosition = .lastSourcePort
                    case .gt:
                        guard port < 65535 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        tempMinSourcePort = port + 1
                        tempMaxSourcePort = 65535
                        linePosition = .lastSourcePort
                    case .lt:
                        guard port > 0 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        tempMinSourcePort = 0
                        tempMaxSourcePort = port - 1
                        linePosition = .lastSourcePort
                    case .range:
                        tempMinSourcePort = port
                        linePosition = .firstSourcePort
                    }
                    //end code snippet A
                case .name(let name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                        return nil
                    }
                    guard let port = possiblePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid source port", line: linenum)
                        return nil
                    }
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "source port operator not found", line: linenum)
                        return nil
                    }
                    switch tempSourcePortOperator {
                    case .eq:
                        tempMinSourcePort = port
                        tempMaxSourcePort = port
                        linePosition = .lastSourcePort
                    case .gt:
                        guard port < 65535 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        tempMinSourcePort = port + 1
                        tempMaxSourcePort = 65535
                        linePosition = .lastSourcePort
                    case .lt:
                        guard port > 0 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid source port \(port)", line: linenum)
                            return nil
                        }
                        tempMinSourcePort = 0
                        tempMaxSourcePort = port - 1
                        linePosition = .lastSourcePort
                    case .range:
                        tempMinSourcePort = port
                        linePosition = .firstSourcePort
                    }
                    //end code snippet A
                }
            case .firstSourcePort:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid source port)", line: linenum)
                    return nil
                case .number(let port):
                    guard let tempMinSourcePort = tempMinSourcePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    guard port >= tempMinSourcePort && port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    tempMaxSourcePort = port
                    linePosition = .lastSourcePort
                case .name(let name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "protocol does not support source port", line: linenum)
                        return nil
                    }
                    guard let port = possiblePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid source port)", line: linenum)
                        return nil
                    }
                    guard let tempMinSourcePort = tempMinSourcePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    guard port >= tempMinSourcePort && port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "error decoding source port range", line: linenum)
                        return nil
                    }
                    tempMaxSourcePort = port
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .host:
                    linePosition = .destIpHost
                case .any:
                    tempMinDestIp = 0
                    tempMaxDestIp = UInt(UInt32.max)
                    linePosition = .destMask
                case .fourOctet(let ipNumber):
                    tempMinDestIp = ipNumber
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let destMask):
                    let numDestHosts: UInt
                    switch type {
                    case .dontCareBit:
                        guard let numDestHostsTemp = destMask.dontCareHosts else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(type)", line: linenum)
                            return nil
                        }
                        numDestHosts = numDestHostsTemp
                    case .netmask:
                        guard let numDestHostsTemp = destMask.netmaskHosts else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(type)", line: linenum)
                            return nil
                        }
                        numDestHosts = numDestHostsTemp
                    case .either:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid after \(linePosition) acl type should be \(type)", line: linenum)
                        return nil
                    }
                    guard tempMinDestIp != nil else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "error decoding destination ip", line: linenum)
                        return nil
                    }
                    let remainder = tempMinDestIp! % numDestHosts
                    if remainder > 0 {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .warning, message: "destination IP not on netmask or bit boundary", line: linenum)
                    }
                    tempMinDestIp = tempMinDestIp! - remainder
                    tempMaxDestIp = tempMinDestIp! + numDestHosts - 1
                    linePosition = .destMask
                }

            case .destIpHost:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .fourOctet(let ipNumber):
                    tempMinDestIp = ipNumber
                    tempMaxDestIp = ipNumber
                case .name(_):
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition) DNS resolution of hostnames is not supported", line: linenum)
                    return nil
                }
                linePosition = .destMask
            case .destMask:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .remark, .comment, .host, .any, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .name(let name):  // only valid for icmp here
                    guard tempIpProtocol == 1, let icmpMessage = IcmpMessage(message: name) else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    self.icmpMessage = icmpMessage
                    debugPrint("warning: specific icmp syntax not supported")
                case .number(let number):
                    guard tempIpProtocol == 1, let icmpMessage = IcmpMessage(type: number, code: nil) else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                        return nil
                    }
                    self.icmpMessage = icmpMessage
                    debugPrint("warning: specific icmp syntax not supported")
                case .established:
                    tempEstablished = true
                    linePosition = .end
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
                
            case .destPortOperator:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    /*guard port >= 0 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }*/
                    //start code snippet B
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "destination port operator not found after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempDestPortOperator {
                        
                    case .eq:
                        tempMinDestPort = port
                        tempMaxDestPort = port
                        linePosition = .lastDestPort
                    case .gt:
                        guard port < 65535 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        tempMinDestPort = port + 1
                        tempMaxDestPort = 65535
                        linePosition = .lastDestPort
                    case .lt:
                        guard port > 0 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        tempMinDestPort = 0
                        tempMaxDestPort = port - 1
                        linePosition = .lastDestPort
                    case .range:
                        tempMinDestPort = port
                        linePosition = .firstDestPort
                    }
                //end code snippet B
                case .name(let name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "protocol \(String(describing: tempIpProtocol)) does not support destination port", line: linenum)
                        return nil
                    }
                    guard let port = possiblePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    //start code snippet B
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "destination port operator not found after \(linePosition)", line: linenum)
                        return nil
                    }
                    switch tempDestPortOperator {
                        
                    case .eq:
                        tempMinDestPort = port
                        tempMaxDestPort = port
                        linePosition = .lastDestPort
                    case .gt:
                        guard port < 65535 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        tempMinDestPort = port + 1
                        tempMaxDestPort = 65535
                        linePosition = .lastDestPort
                    case .lt:
                        guard port > 0 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum)
                            delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                            return nil
                        }
                        tempMinDestPort = 0
                        tempMaxDestPort = port - 1
                        linePosition = .lastDestPort
                    case .range:
                        tempMinDestPort = port
                        linePosition = .firstDestPort
                    }
                    //end code snippet B
                }
            case .firstDestPort:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                    return nil
                case .number(let port):
                    guard let tempMinDestPort = tempMinDestPort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    guard port >= tempMinDestPort && port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    tempMaxDestPort = port
                    linePosition = .lastDestPort
                case .name(let name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "protocol \(String(describing: tempIpProtocol)) does not support destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    guard let port = possiblePort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    guard let tempMinDestPort = tempMinDestPort else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    guard port >= tempMinDestPort && port < 65536 else {
                        delegate?.report(severity: .linetext, message: line, line: linenum)
                        delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                        return nil
                    }
                    tempMaxDestPort = port
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .gt, .lt, .number, .name, .host, .any, .fourOctet:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid destination port after \(linePosition)", line: linenum)
                    return nil
                case .log:
                    linePosition = .end
                case .comment:
                    linePosition = .comment
                case .established:
                    tempEstablished = true
                    linePosition = .end
                }

            case .end:
                switch token {
                case .log:
                    break  // do nothing
                case .comment:
                    linePosition = .comment
                default:
                    delegate?.report(severity: .linetext, message: line, line: linenum)
                    delegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum)
                    return nil
                }
            case .comment:
                break // do nothing, we are in a comment
            case .remark:
                return nil
            }
        }
        
        guard tempAclAction != nil else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "no acl action found", line: linenum)
            return nil
        }
        self.aclAction = tempAclAction!
        self.ipVersion = .IPv4
        self.listName = tempListName
        
        //guard tempIpProtocol != nil else {
        guard let localTempIpProtocol = tempIpProtocol else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "no protocol found", line: linenum)
            return nil
        }
        switch localTempIpProtocol {
        case 6, 17:
            break
        case 0...255:
            if tempMinSourcePort != nil || tempMaxSourcePort != nil || tempMinDestPort != nil || tempMaxSourcePort != nil {
                delegate?.report(severity: .linetext, message: line, line: linenum)
                delegate?.report(severity: .error, message: "Only protocols tcp and udp support port numbers", line: linenum)
                return nil
            }
        default:
            // should not get here
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "Unable to identify ip protocol", line: linenum)
        }
        self.ipProtocol = localTempIpProtocol
        
        guard tempMinSourceIp != nil else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "source ip not found", line: linenum)
            return nil
        }
        self.minSourceIp = tempMinSourceIp!
        
        guard tempMaxSourceIp != nil else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "source ip not found", line: linenum)
            return nil
        }
        self.maxSourceIp = tempMaxSourceIp!
        
        self.minSourcePort = tempMinSourcePort ?? 0
        self.maxSourcePort = tempMaxSourcePort ?? 65535
        
        guard tempMinDestIp != nil else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "dest ip not found", line: linenum)
            return nil
        }
        self.minDestIp = tempMinDestIp!
        
        guard tempMaxDestIp != nil else {
            delegate?.report(severity: .linetext, message: line, line: linenum)
            delegate?.report(severity: .error, message: "dest ip not found", line: linenum)
            return nil
        }
        self.maxDestIp = tempMaxDestIp!
        
        self.minDestPort = tempMinDestPort ?? 0
        self.maxDestPort = tempMaxDestPort ?? 65535
        
        self.established = tempEstablished
        self.line = line

        debugPrint(self)
        
    }
    func analyze(socket: Socket) -> AclAction {
        // check ip protocol
        guard self.ipProtocol == 0 || self.ipProtocol == socket.ipProtocol else {
            return .neither
        }
        // check source ip
        guard socket.sourceIp >= self.minSourceIp && socket.sourceIp <= self.maxSourceIp else {
            return .neither
        }
        // check destination ip
        guard socket.destinationIp >= self.minDestIp && socket.destinationIp <= self.maxDestIp else {
            return .neither
        }
        // check ports if protocol udp or tcp
        if socket.ipProtocol == 17 || socket.ipProtocol == 6 {
            if let minSourcePort = minSourcePort, let socketSourcePort = socket.sourcePort {
                guard socketSourcePort >= minSourcePort else {
                    return .neither
                }
            }
            if let maxSourcePort = maxSourcePort, let socketSourcePort = socket.sourcePort {
                guard socketSourcePort <= maxSourcePort else {
                    return .neither
                }
            }
            if let minDestPort = minDestPort, let socketDestPort = socket.destinationPort {
                guard socketDestPort >= minDestPort else {
                    return .neither
                }
            }
            if let maxDestPort = maxDestPort, let socketDestPort = socket.destinationPort {
                guard socketDestPort <= maxDestPort else {
                    return .neither
                }
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
        
        var returnString = "\(aclAction) \(ipVersion) \(ipProtocol.ipProto) \(minSourceIp.ipv4) through \(maxSourceIp.ipv4) source ports \(String(describing: minSourcePort))-\(String(describing: maxSourcePort)) to \(minDestIp.ipv4) through \(maxDestIp.ipv4) dest ports \(String(describing: minDestPort))-\(String(describing: maxDestPort))"
        if self.established {
            returnString.append(" established\n")
        } else {
            returnString.append("\n")
        }
        return returnString
    }
}

