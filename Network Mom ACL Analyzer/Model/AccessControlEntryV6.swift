//
//  AccessControlEntryV6.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 8/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//
/*
import Foundation

struct AccessControlEntryV6 {
    static let ANYIPV6RANGE: IpRangeV6 = IpRangeV6(minIp: 0, maxIp: UInt128.max)
    
    var aclAction: AclAction = .neither  // neither means not initialized
    var ipVersion: IpVersion = .IPv6
    var listName: String?
    var ipProtocols: [UInt] = []  // 0 means ip
    var sourceIp: [IpRangeV6] = []
    var sourcePort: [PortRange] = []  //empty list means no port restriction
    var destIp: [IpRangeV6] = []
    var destPort: [PortRange] = []  // empty means no port restriction
    var established: Bool = false
    var line: String
    var linenum: Int
    var log = false
    var icmpMessages: [IcmpMessage] = []
    var sequence: UInt?  // If a sequence number exists in the line
    
    enum IosLinePosition {
        case beginning
        case sequence
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourcePortOperator
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destPortOperator
        case firstDestPort
        case lastDestPort
        case flags
        case comment // comment spotted, can ignore everything from here on
        case end // end without comment, still need to check syntax
    }

    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?) {
        
        switch deviceType {
        case .iosv6:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, iosv6: true)
        case .asa:
            fatalError("ipv6 .asa not implemented")
        case .ios:
            fatalError("ipv6 .ios not implemented")
        case .nxos:
            fatalError("ipv6 .nxos not implemented")
        case .iosxr:
            fatalError("ipv6 .iosxr not implemented")
        case .arista:
            fatalError("ipv6 .arista not implemented")
        }
    }
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, iosv6: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: IosLinePosition = .beginning

        self.line = line
        self.linenum = linenum

        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }

        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }
        
        func validateIos() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }

            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(PortRange.ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(PortRange.ANYPORTRANGE)
                }
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(PortRange.ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(PortRange.ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
                if self.established == true { return false }
            default:
                // should not get here
                return false
            }
            return true
        }//ValidateIos

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        wordLoop: for word in words {
            guard let token = IosTokenV6(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any,.host,.portOperator,.log,.established,.name,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .comment:
                    return nil
                case .number(let sequence):
                    self.sequence = sequence
                    linePosition = .sequence
                }//switch linePosition
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any,.host,.portOperator,.log,.established,.name,.addressV6,.cidrV6,.number:
                    reportError()
                    return nil
                case .comment:
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.name:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    guard ipProtocol < 256 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portOperator,.comment,.log,.established,.addressV6,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [AccessControlEntryV6.ANYIPV6RANGE]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidrV6(let ipV6Range):
                    self.sourceIp = [ipV6Range]
                    linePosition = .sourceIp
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let address):
                    let ipRangeV6 = IpRangeV6(minIp: address, maxIp: address)
                    self.sourceIp = [ipRangeV6]
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.comment,.log,.established,.addressV6,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntryV6.ANYIPV6RANGE]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let sourcePortOperator):
                    tempSourcePortOperator = sourcePortOperator
                    linePosition = .sourcePortOperator
                case .cidrV6(let ipV6Range):
                    self.destIp = [ipV6Range]
                    linePosition = .destIp
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let port):
                    guard let tempFirstSourcePort = tempFirstSourcePort, port <= UInt.MAXPORT, tempSourcePortOperator == .range, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = name.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = name.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstSourcePort = tempFirstSourcePort, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portOperator,.comment,.log,.established,.addressV6,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntryV6.ANYIPV6RANGE]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidrV6(let ipRangeV6):
                    self.destIp = [ipRangeV6]
                    linePosition = .destIp
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let address):
                    let ipRangeV6 = IpRangeV6(minIp: address, maxIp: address)
                    self.destIp = [ipRangeV6]
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstDestPort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard let tempFirstDestPort = tempFirstDestPort, secondDestPort <= UInt.MAXPORT, tempDestPortOperator == .range, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = secondPortString.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = secondPortString.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstDestPort = tempFirstDestPort, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .flags:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .comment:
                linePosition = .comment
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.portOperator,.established,.number,.name,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            }
        }//wordLoop for word in words
        if validateIos() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }// init ios
}
*/
