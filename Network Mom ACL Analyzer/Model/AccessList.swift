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
    init(sourceText: String) {
        self.sourceText = sourceText
        var linenum = 0
        lineLoop: for line in sourceText.components(separatedBy: NSCharacterSet.newlines) {
            linenum = linenum + 1
            if line.isEmpty {
                debugPrint("line \(linenum) is empty")
                continue lineLoop
            }
            let words = line.components(separatedBy: NSCharacterSet.whitespaces)
            if words.count < 2 {
                continue lineLoop
            }
            var linePosition: LinePosition = .accessList
            var candidate = AccessControlEntryCandidate()
            wordLoop: for word in words {
                if word.first == "!" {
                    continue lineLoop
                }
                switch linePosition {
                    
                case .accessList:
                    if word == "access-list" {
                        linePosition = .listName
                        continue wordLoop
                    } else {
                        linePosition = .action
                        candidate.aclAction = findAction(word: word)
                        linePosition = .ipProtocol
                        if candidate.aclAction == nil {
                            debugPrint("line \(line) invalid at aclAction")
                            continue lineLoop
                        }
                    }
                case .listName:
                    candidate.listName = word
                    linePosition = .action
                case .action:
                    candidate.aclAction = findAction(word: word)
                    if candidate.aclAction == nil {
                        debugPrint("line \(line) invalid at aclAction")
                        continue lineLoop
                    }
                    linePosition = .ipProtocol

                case .ipProtocol:
                    switch word {
                    case "tcp":
                        candidate.ipProtocol = 6
                    case "udp":
                        candidate.ipProtocol = 17
                    case "ip":
                        candidate.ipProtocol = 0
                    default:
                        debugPrint("line \(line) invalid at ipProtocol")
                        continue lineLoop
                    }
                    linePosition = .sourceIp
                case .sourceIp:
                    if word == "any" {
                        candidate.leastSourceIp = 0
                        candidate.maxSourceIp = UInt32.max
                        linePosition = .destIp
                        continue wordLoop
                    }
                    if word == "host" {
                        linePosition = .sourceIpHost
                        continue wordLoop
                    }
                    guard let _ = IPv4Address(word) else {
                        debugPrint("line \(line) invalid at sourceIp")
                        continue lineLoop
                    }
                    candidate.leastSourceIp = word.ipv4address
                    linePosition = .sourceMask
                    if candidate.leastSourceIp == nil {
                        debugPrint("line \(line) invalid at sourceIp")
                        continue lineLoop
                    }
                case .sourceIpHost:
                    candidate.leastSourceIp = word.ipv4address
                    candidate.maxSourceIp = candidate.leastSourceIp
                    if candidate.leastSourceIp == nil {
                        debugPrint("line \(line) invalid at sourceIpHost")
                        continue lineLoop
                    }
                case .sourceMask:
                    guard let sourceMask = word.ipv4address else {
                        debugPrint("line \(line) invalid at sourceMask")
                        continue lineLoop
                    }
                    let numHosts = (4294967295 - sourceMask) + 1
                    guard let leastSourceIp = candidate.leastSourceIp else {
                        debugPrint(" line \(line) unable to find leastSourceIp at sourceMask")
                        continue lineLoop
                    }
                    candidate.maxSourceIp = leastSourceIp + (numHosts - 1)
                    linePosition = .destIp
                case .destIp:
                    if word == "any" {
                        candidate.leastDestIp = 0
                        candidate.maxDestIp = UInt32.max
                        linePosition = .portQualifier
                        continue wordLoop
                    }
                    if word == "host" {
                        linePosition = .destIpHost
                        continue wordLoop
                    }
                    guard let _ = IPv4Address(word) else {
                        debugPrint("line \(line) invalid at destIp")
                        continue lineLoop
                    }
                    candidate.leastDestIp = word.ipv4address
                    linePosition = .destMask
                    if candidate.leastDestIp == nil {
                        debugPrint("line \(line) invalid at destIp")
                        continue lineLoop
                    }

                case .destIpHost:
                    candidate.leastDestIp = word.ipv4address
                    candidate.maxDestIp = candidate.leastDestIp
                    if candidate.leastDestIp == nil {
                        debugPrint("line \(line) invalid at destIpHost")
                        continue lineLoop
                    }
                case .destMask:
                    guard let destMask = word.ipv4address else {
                        debugPrint("line \(line) invalid at destMask")
                        continue lineLoop
                    }
                    let numHosts = (4294967295 - destMask) + 1
                    guard let leastDestIp = candidate.leastDestIp else {
                        debugPrint(" line \(line) unable to find leastDestIp at destMask")
                        continue lineLoop
                    }
                    candidate.maxDestIp = leastDestIp + (numHosts - 1)
                    linePosition = .portQualifier
                case .portQualifier:
                    linePosition = .firstPort
                    debugPrint(" line \(line) portQualifier not implemented")
                case .firstPort:
                    linePosition = .lastPort
                    debugPrint(" line \(line) firstPort not implemented")

                case .lastPort:
                    debugPrint(" line \(line) lastPort not implemented")

                }
            }
        }
    }
}
