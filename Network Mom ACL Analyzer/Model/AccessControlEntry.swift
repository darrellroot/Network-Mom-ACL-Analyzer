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
    var ipProtocol: UInt
    var minSourceIp: UInt
    var maxSourceIp: UInt
    var minSourcePort: UInt?
    var maxSourcePort: UInt?
    var minDestIp: UInt
    var maxDestIp: UInt
    var minDestPort: UInt?
    var maxDestPort: UInt?
    var established: Bool
    var line: String?
    
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
        if words.count < 2 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = AclToken(string: word) else {
                debugPrint("line \(line) invalid at \(linePosition)")
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .remark:
                    linePosition = .remark
                    debugPrint("line \(line) has remark")
                    return nil
                case .comment:
                    linePosition = .comment
                    continue wordLoop
                }
            case .accessList:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq , .range, .remark, .comment, .gt, .lt, .established, .log, .fourOctet, .host, .any:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .permit:
                    tempAclAction = .permit
                    linePosition = .action
                case .deny:
                    tempAclAction = .deny
                    linePosition = .action
                case .remark:
                    debugPrint("line \(line) has remark")
                    return nil
                }
            case .action:
                switch token {
                
                case .accessList, .permit, .deny, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .fourOctet, .name, .host, .any:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                        debugPrint("line \(line) invalid ip protocol after \(linePosition)")
                        return nil
                    } else {
                        tempIpProtocol = number
                        linePosition = .ipProtocol
                    }
                }
            case .ipProtocol:
                switch token {
                    
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .fourOctet(let sourceMask):
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
                    guard tempMinSourceIp != nil else {
                        debugPrint(" line \(line) unable to find tempMinSourceIp at sourceMask")
                        return nil
                    }
                    let remainder = tempMinSourceIp! % numSourceHosts
                    if remainder > 0 {
                        debugPrint("warning line \(line) destination IP not on netmask or bit boundary\n")
                    }
                    tempMinSourceIp = tempMinSourceIp! - remainder
                    tempMaxSourceIp = tempMinSourceIp! + numSourceHosts - 1
                    
                    linePosition = .sourceMask
                }
                
            case .sourceIpHost:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number:
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .fourOctet(let ipNumber):
                    tempMinSourceIp = ipNumber
                    tempMaxSourceIp = ipNumber
                case .name(_):
                    debugPrint("line \(line) invalid after \(linePosition) DNS resolution of hostnames is not supported")
                    return nil
                }
                linePosition = .sourceMask
            case .sourceMask:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .remark, .comment, .number, .name, .established, .log:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        debugPrint("line \(line) invalid source port \(port)")
                        return nil
                    }
                    guard port >= 0 else {
                        debugPrint("line \(line) invalid source port \(port)")
                        return nil
                    }
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        debugPrint("line \(line) error sourcePortOperator not found")
                        return nil
                    }
                    switch tempSourcePortOperator {
                        
                    case .eq:
                        tempMinSourcePort = port
                        tempMaxSourcePort = port
                        linePosition = .lastSourcePort
                    case .gt:
                        guard port < 65535 else {
                            debugPrint("line \(line) invalid source port \(port)")
                            return nil
                        }
                        tempMinSourcePort = port + 1
                        tempMaxSourcePort = 65535
                        linePosition = .lastSourcePort
                    case .lt:
                        guard port > 0 else {
                            debugPrint("line \(line) invalid source port \(port)")
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
                case .name(var name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        debugPrint("line \(line) protocol does not support source port")
                        return nil
                    }
                    guard let port = possiblePort else {
                        debugPrint("line \(line) invalid source port")
                        return nil
                    }
                    //start code snippet A
                    guard let tempSourcePortOperator = tempSourcePortOperator else {
                        debugPrint("line \(line) error sourcePortOperator not found")
                        return nil
                    }
                    switch tempSourcePortOperator {
                    case .eq:
                        tempMinSourcePort = port
                        tempMaxSourcePort = port
                        linePosition = .lastSourcePort
                    case .gt:
                        guard port < 65535 else {
                            debugPrint("line \(line) invalid source port \(port)")
                            return nil
                        }
                        tempMinSourcePort = port + 1
                        tempMaxSourcePort = 65535
                        linePosition = .lastSourcePort
                    case .lt:
                        guard port > 0 else {
                            debugPrint("line \(line) invalid source port \(port)")
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
                    debugPrint("line \(line) invalid source port")
                    return nil
                case .number(let port):
                    guard let tempMinSourcePort = tempMinSourcePort else {
                        debugPrint("line \(line) error decoding source port range")
                        return nil
                    }
                    guard port >= tempMinSourcePort && port < 65536 else {
                        debugPrint("line \(line) error decoding source port range")
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
                        debugPrint("line \(line) protocol does not support source port")
                        return nil
                    }
                    guard let port = possiblePort else {
                        debugPrint("line \(line) invalid source port")
                        return nil
                    }
                    guard let tempMinSourcePort = tempMinSourcePort else {
                        debugPrint("line \(line) error decoding source port range")
                        return nil
                    }
                    guard port >= tempMinSourcePort && port < 65536 else {
                        debugPrint("line \(line) error decoding source port range")
                        return nil
                    }
                    tempMaxSourcePort = port
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .comment, .gt, .lt, .established, .log, .number, .name:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .fourOctet(let destMask):
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
                        debugPrint("line \(line) unknown acl type \(type)")
                        return nil
                    }
                    guard tempMinDestIp != nil else {
                        debugPrint(" line \(line) unable to find tempMinDestIp at destMask")
                        return nil
                    }
                    let remainder = tempMinDestIp! % numDestHosts
                    if remainder > 0 {
                        debugPrint("warning line \(line) destination IP not on netmask or bit boundary\n")
                    }
                    tempMinDestIp = tempMinDestIp! - remainder
                    tempMaxDestIp = tempMinDestIp! + numDestHosts - 1
                    linePosition = .destMask
                }

            case .destIpHost:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .host, .any, .remark, .comment, .gt, .lt, .established, .log, .number:
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .fourOctet(let ipNumber):
                    tempMinDestIp = ipNumber
                    tempMaxDestIp = ipNumber
                case .name(_):
                    debugPrint("line \(line) invalid after \(linePosition) DNS resolution of hostnames is not supported")
                    return nil
                }
                linePosition = .destMask
            case .destMask:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .remark, .comment, .number, .host, .any, .name, .established, .fourOctet:
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
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
                    debugPrint("line \(line) invalid after \(linePosition)")
                    return nil
                case .number(let port):
                    guard port < 65536 else {
                        debugPrint("line \(line) invalid dest port \(port)")
                        return nil
                    }
                    guard port >= 0 else {
                        debugPrint("line \(line) invalid dest port \(port)")
                        return nil
                    }
                    //start code snippet B
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        debugPrint("line \(line) error destPortOperator not found")
                        return nil
                    }
                    switch tempDestPortOperator {
                        
                    case .eq:
                        tempMinDestPort = port
                        tempMaxDestPort = port
                        linePosition = .lastDestPort
                    case .gt:
                        guard port < 65535 else {
                            debugPrint("line \(line) invalid dest port \(port)")
                            return nil
                        }
                        tempMinDestPort = port + 1
                        tempMaxDestPort = 65535
                        linePosition = .lastDestPort
                    case .lt:
                        guard port > 0 else {
                            debugPrint("line \(line) invalid dest port \(port)")
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
                case .name(var name):
                    let possiblePort: UInt?
                    switch tempIpProtocol {
                    case 6:  // tcp
                        possiblePort = name.tcpPort
                    case 17: //udp
                        possiblePort = name.udpPort
                    default:
                        debugPrint("line \(line) protocol does not support dest port")
                        return nil
                    }
                    guard let port = possiblePort else {
                        debugPrint("line \(line) invalid dest port")
                        return nil
                    }
                    //start code snippet B
                    guard let tempDestPortOperator = tempDestPortOperator else {
                        debugPrint("line \(line) error destPortOperator not found")
                        return nil
                    }
                    switch tempDestPortOperator {
                        
                    case .eq:
                        tempMinDestPort = port
                        tempMaxDestPort = port
                        linePosition = .lastDestPort
                    case .gt:
                        guard port < 65535 else {
                            debugPrint("line \(line) invalid dest port \(port)")
                            return nil
                        }
                        tempMinDestPort = port + 1
                        tempMaxDestPort = 65535
                        linePosition = .lastDestPort
                    case .lt:
                        guard port > 0 else {
                            debugPrint("line \(line) invalid dest port \(port)")
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
                    debugPrint("line \(line) invalid dest port")
                    return nil
                case .number(let port):
                    guard let tempMinDestPort = tempMinDestPort else {
                        debugPrint("line \(line) error decoding dest port range")
                        return nil
                    }
                    guard port >= tempMinDestPort && port < 65536 else {
                        debugPrint("line \(line) error decoding dest port range")
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
                        debugPrint("line \(line) protocol does not support dest port")
                        return nil
                    }
                    guard let port = possiblePort else {
                        debugPrint("line \(line) invalid dest port")
                        return nil
                    }
                    guard let tempMinDestPort = tempMinDestPort else {
                        debugPrint("line \(line) error decoding dest port range")
                        return nil
                    }
                    guard port >= tempMinDestPort && port < 65536 else {
                        debugPrint("line \(line) error decoding dest port range")
                        return nil
                    }
                    tempMaxDestPort = port
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .accessList, .permit, .deny, .tcp, .ip, .udp, .icmp, .eq, .range, .remark, .gt, .lt, .number, .name, .host, .any, .fourOctet:
                    debugPrint("line \(line) invalid after \(linePosition)")
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
                    debugPrint("line \(line) invalid at end")
                    return nil
                }
            case .comment:
                break // do nothing, we are in a comment
            case .remark:
                return nil
            }
        }
        
        guard tempAclAction != nil else {
            debugPrint("line \(line) no acl action found")
            return nil
        }
        self.aclAction = tempAclAction!
        self.ipVersion = .IPv4
        self.listName = tempListName
        
        guard tempIpProtocol != nil else {
            debugPrint("line \(line) no ip protocol found")
            return nil
        }
        self.ipProtocol = tempIpProtocol!
        
        guard tempMinSourceIp != nil else {
            debugPrint("line \(line) source ip not found")
            return nil
        }
        self.minSourceIp = tempMinSourceIp!
        
        guard tempMaxSourceIp != nil else {
            debugPrint("line \(line) source ip not found")
            return nil
        }
        self.maxSourceIp = tempMaxSourceIp!
        
        self.minSourcePort = tempMinSourcePort ?? 0
        self.maxSourcePort = tempMaxSourcePort ?? 65535
        
        guard tempMinDestIp != nil else {
            debugPrint("line \(line) dest ip not found")
            return nil
        }
        self.minDestIp = tempMinDestIp!
        
        guard tempMaxDestIp != nil else {
            debugPrint("line \(line) dest ip not found")
            return nil
        }
        self.maxDestIp = tempMaxDestIp!
        
        self.minDestPort = tempMinDestPort ?? 0
        self.maxDestPort = tempMaxDestPort ?? 65535
        
        self.established = tempEstablished
        self.line = line

        debugPrint(self)
        
    }
}

extension AccessControlEntry: CustomStringConvertible {
    var description: String {
        
        var returnString = "\(aclAction) \(ipVersion) \(ipProtocol.ipProto) \(minSourceIp.ipv4) through \(maxSourceIp.ipv4) source ports \(minSourcePort)-\(maxSourcePort) to \(minDestIp.ipv4) through \(maxDestIp.ipv4) dest ports \(minDestPort)-\(maxDestPort)"
        if self.established {
            returnString.append(" established\n")
        } else {
            returnString.append("\n")
        }
        return returnString
    }
}

