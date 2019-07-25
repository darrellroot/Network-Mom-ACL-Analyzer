//
//  RandomAcl.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/24/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct RandomAcl: CustomStringConvertible {
    
    static let protocols = ["ip","tcp","udp","6","17","gre"]
    
    var deviceType: DeviceType
    var aclAction: AclAction
    var ipProtocol: String
    var sourceIp: UInt
    var sourcePrefix: Ipv4Prefix
    //var sourceDontCare: UInt
    let sourceLowPort: UInt
    let sourceHighPort: UInt
    var sourcePortOperator: PortOperator
    var destIp: UInt
    let destPrefix: Ipv4Prefix
    //var destDontCare: UInt
    let destLowPort: UInt
    let destHighPort: UInt
    var destPortOperator: PortOperator
    
    init(deviceType: DeviceType) {
        self.deviceType = deviceType
        let sourceIp = UInt.random(in: 0...UInt(UInt32.max))
        self.sourcePrefix = Ipv4Prefix.allCases.randomElement()!
        //let sourceDontCare = self.sourcePrefix.dontCareHosts
        //self.sourceDontCare = RandomAcl.dontcareMasks.randomElement()!
        let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
        self.sourceIp = sourceIp - sourceRemainder
        let destIp = UInt.random(in: 0...UInt(UInt32.max))
        self.destPrefix = Ipv4Prefix.allCases.randomElement()!
        //self.destDontCare = RandomAcl.dontcareMasks.randomElement()!
        let destRemainder = destIp % self.destPrefix.dontCareHosts
        self.destIp = destIp - destRemainder
        self.ipProtocol = RandomAcl.protocols.randomElement()!
        
        self.aclAction = [.permit,.deny].randomElement()!
        
        let port1 = UInt.random(in: 0...UInt.MAXPORT)
        let port2 = UInt.random(in: 0...UInt.MAXPORT)
        let port3 = UInt.random(in: 0...UInt.MAXPORT)
        let port4 = UInt.random(in: 0...UInt.MAXPORT)
        if port1 < port2 {
            self.sourceLowPort = port1
            self.sourceHighPort = port2
        } else {
            self.sourceLowPort = port2
            self.sourceHighPort = port1
        }
        if port3 < port4 {
            self.destLowPort = port3
            self.destHighPort = port4
        } else {
            self.destLowPort = port4
            self.destHighPort = port3
        }
        let a = PortOperator.allCases
        let b = a.randomElement()!
        self.sourcePortOperator = b
        self.destPortOperator = PortOperator.allCases.randomElement()!
        self.ipProtocol = RandomAcl.protocols.randomElement()!
    }
    
    var description: String {
        var outputString = ""
        if self.deviceType == .asa {
            outputString.append("access-list 101 extended ")
        }
        outputString.append("\(aclAction) \(ipProtocol) \(self.sourceIp.ipv4)")
        switch self.deviceType {
        case .ios, .iosxr:
            outputString.append(" \(sourcePrefix.dontCareBits) ")
        case .asa:
            outputString.append(" \(sourcePrefix.netmask) ")
        case .nxos:
            outputString.append("/\(sourcePrefix.rawValue) ")
        case .arista:
            fatalError("Not implemented")
        }
        switch ipProtocol {
        case "tcp","udp","6","17":
            switch sourcePortOperator {
            case .eq,.gt,.lt:
                outputString.append("\(sourcePortOperator) \(sourceLowPort)")
            case .ne:
                outputString.append("neq \(sourceLowPort)")
            case .range:
                outputString.append("\(sourcePortOperator) \(sourceLowPort) \(sourceHighPort)")
//            case .nothing:
//                sourcePortString = ""
            }
        default:
            break
        }//switch ipProtocol for source ports
        outputString.append(" \(self.destIp.ipv4)")
        switch self.deviceType {
        case .ios, .iosxr:
            outputString.append(" \(destPrefix.dontCareBits) ")
        case .asa:
            outputString.append(" \(destPrefix.netmask) ")
        case .nxos:
            outputString.append("/\(destPrefix.rawValue) ")
        case .arista:
            fatalError("Not implemented")
        }
        switch ipProtocol {
        case "tcp","udp","6","17":
            switch destPortOperator {
            case .eq,.gt,.lt:
                outputString.append("\(destPortOperator) \(destLowPort)")
            case .ne:
                outputString.append("neq \(destLowPort)")
            case .range:
                outputString.append("\(destPortOperator) \(destLowPort) \(destHighPort)")
                //            case .nothing:
                //                destPortString = ""
            }
        default:
            break
        }// switch ipProtocol for dest ports
        switch ipProtocol {
        case "tcp","6":
            if Bool.random() && deviceType != .asa {
                outputString.append(" established")
            } else {
                break
            }
        default:
            break
        }
        if Bool.random() {
            outputString.append( " log")
        }
        outputString.append("\n")
        return outputString
    }
    
    static func operation() -> String {
        //let valid = Bool.random()
        let portOperator = PortOperator.allCases.randomElement()!
        var portOperatorString: String = ""
        let port1 = UInt.random(in: 0...UInt.MAXPORT)
        let port2 = UInt.random(in: 0...UInt.MAXPORT)
        switch portOperator {
        case .eq:
            portOperatorString = "\(portOperator) \(port1)"
        case .gt:
            portOperatorString = "\(portOperator) \(port1)"
        case .lt:
            portOperatorString = "\(portOperator) \(port1)"
        case .ne:
            portOperatorString = "\(portOperator) \(port1)"
        case .range:
            if port1 <= port2 {
                portOperatorString = "\(portOperator) \(port1) \(port2)"
            } else {
                portOperatorString = "\(portOperator) \(port2) \(port1)"
            }
        }//switch portOperator
        return portOperatorString
    }
}
