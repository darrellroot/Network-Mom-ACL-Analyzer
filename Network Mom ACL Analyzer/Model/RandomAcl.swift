//
//  RandomAcl.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/24/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct RandomAcl: CustomStringConvertible {
    static var staticSequence: Int = 1
    var sequence: Int
    var myDescription: String
    
    static let protocols = ["ip","tcp","udp","6","17","gre"]
    static let protocolsv6 = ["ipv6","tcp","udp","6","17","ahp"]

    //var deviceType: DeviceType
    //var aclAction: AclAction
    //var ipProtocol: String
    //let sourceV6cidr: Cidr  // only used for ipv6 case
    //var sourceIp: UInt128
    //var sourcePrefix: Ipv4Prefix
    //var sourceDontCare: UInt
    //let sourceLowPort: UInt
    //let sourceHighPort: UInt
    //var sourcePortOperator: PortOperator
    //var destIp: UInt128
    //let destPrefix: Ipv4Prefix
    //let destV6cidr: Cidr // only used for ipv6 case
    //var destDontCare: UInt
    //let destLowPort: UInt
    //let destHighPort: UInt
    //var destPortOperator: PortOperator
    
    init(deviceType: DeviceType) {
        
        //self.deviceType = deviceType
        
        self.sequence = RandomAcl.staticSequence
        if deviceType == .iosxr {
            RandomAcl.staticSequence = RandomAcl.staticSequence + 1
        }
        
        /*let sourceV6 = UInt128.random(in: 0...UInt128.max)
        let sourceV6Prefix = UInt.random(in: 0...128)
        let sourceV6String = "\(sourceV6.ipv6)/\(sourceV6Prefix)"
        self.sourceV6cidr = Cidr(cidr: sourceV6String)!  //TODO get rid of !
        let destV6 = UInt128.random(in: 0...UInt128.max)
        let destV6Prefix = UInt.random(in: 0...128)
        let destV6String = "\(destV6.ipv6)/\(destV6Prefix)"
        self.destV6cidr = Cidr(cidr: destV6String)!  //TODO get rid of !*/
        
        //let sourceDontCare = self.sourcePrefix.dontCareHosts
        //self.sourceDontCare = RandomAcl.dontcareMasks.randomElement()!
        //let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
        //self.sourceIp = sourceIp - sourceRemainder
        //let destIp = UInt.random(in: 0...UInt(UInt32.max))
        //self.destPrefix = Ipv4Prefix.allCases.randomElement()!
        //self.destDontCare = RandomAcl.dontcareMasks.randomElement()!
        //let destRemainder = destIp % self.destPrefix.dontCareHosts
        //self.destIp = destIp - destRemainder
        
        //var sourceIp: UInt
        //let sourcePrefix: Ipv4Prefix
        //var destIp: UInt
        //let destPrefix: Ipv4Prefix
        
        //let sourceV6cidr: Cidr
        //let destV6cidr: Cidr
        let sourceString, destString: String
        
        switch deviceType {
        
        case .ios,.iosxr:
            var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
            let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
            let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
            sourceIp = sourceIp - sourceRemainder
            
            var destIp = UInt.random(in: 0...UInt(UInt32.max))
            let destPrefix = Ipv4Prefix.allCases.randomElement()!
            let destRemainder = destIp % destPrefix.dontCareHosts
            destIp = destIp - destRemainder
            
            sourceString = "\(sourceIp.ipv4) \(sourcePrefix.dontCareBits) "
            destString = " \(destIp.ipv4) \(destPrefix.dontCareBits) "
        
        case .asa:
            var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
            let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
            let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
            sourceIp = sourceIp - sourceRemainder
            
            var destIp = UInt.random(in: 0...UInt(UInt32.max))
            let destPrefix = Ipv4Prefix.allCases.randomElement()!
            let destRemainder = destIp % destPrefix.dontCareHosts
            destIp = destIp - destRemainder
            
            sourceString = "\(sourceIp.ipv4) \(sourcePrefix.netmask) "
            destString = " \(destIp.ipv4) \(destPrefix.netmask) "
        case .nxos:
            var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
            let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
            let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
            sourceIp = sourceIp - sourceRemainder
            
            var destIp = UInt.random(in: 0...UInt(UInt32.max))
            let destPrefix = Ipv4Prefix.allCases.randomElement()!
            let destRemainder = destIp % destPrefix.dontCareHosts
            destIp = destIp - destRemainder
            
            sourceString = "\(sourceIp.ipv4)/\(sourcePrefix.rawValue) "
            destString = " \(destIp.ipv4)/\(destPrefix.rawValue) "

        case .arista:
            fatalError("Not implemented")
        case .iosv6,.nxosv6:
            let sourceV6 = UInt128.random(in: 0...UInt128.max)
            let sourceV6Prefix = UInt.random(in: 0...128)
            let sourceV6String = "\(sourceV6.ipv6)/\(sourceV6Prefix)"
            let sourceV6cidr = Cidr(cidr: sourceV6String)!  //TODO get rid of !
            sourceString = "\(sourceV6cidr) "
            
            let destV6 = UInt128.random(in: 0...UInt128.max)
            let destV6Prefix = UInt.random(in: 0...128)
            let destV6String = "\(destV6.ipv6)/\(destV6Prefix)"
            let destV6cidr = Cidr(cidr: destV6String)!  //TODO get rid of !
            destString = " \(destV6cidr) "
            
        }
        let aclAction: AclAction = [.permit,.deny].randomElement()!
        
        let port1 = UInt.random(in: 0...UInt.MAXPORT)
        let port2 = UInt.random(in: 0...UInt.MAXPORT)
        let port3 = UInt.random(in: 0...UInt.MAXPORT)
        let port4 = UInt.random(in: 0...UInt.MAXPORT)
        let sourceLowPort, sourceHighPort, destLowPort, destHighPort: UInt
        if port1 < port2 {
            sourceLowPort = port1
            sourceHighPort = port2
        } else {
            sourceLowPort = port2
            sourceHighPort = port1
        }
        if port3 < port4 {
            destLowPort = port3
            destHighPort = port4
        } else {
            destLowPort = port4
            destHighPort = port3
        }
        let sourcePortOperator = PortOperator.allCases.randomElement()!
        let destPortOperator = PortOperator.allCases.randomElement()!
        
        let ipProtocol: String
        switch deviceType {
            
        case .ios,.asa,.nxos,.iosxr:
            ipProtocol = RandomAcl.protocols.randomElement()!
        case .iosv6,.nxosv6:
            ipProtocol = RandomAcl.protocolsv6.randomElement()!
        case .arista:
            fatalError("not implemented")
        }
        
        var outputString = ""
        if deviceType == .asa {
            outputString.append("access-list 101 extended ")
        }
        if deviceType == .iosxr {
            let sequenceString = String(format: "%4d ", self.sequence)
            outputString.append(sequenceString)
        }
        outputString.append("\(aclAction) \(ipProtocol) ")
        switch deviceType {
        case .ios, .iosxr:
            outputString.append(sourceString)
        case .asa:
            outputString.append(sourceString)
        case .nxos:
            outputString.append(sourceString)
        case .nxosv6:
            outputString.append(sourceString)
        case .arista:
            fatalError("Not implemented")
        case .iosv6:
            outputString.append(sourceString)
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
        //outputString.append(" \(self.destIp.ipv4)")
        switch deviceType {
        case .ios, .iosxr:
            outputString.append(destString)
        case .asa:
            outputString.append(destString)
        case .nxos:
            outputString.append(destString)
        case .arista:
            fatalError("Not implemented")
        case .iosv6,.nxosv6:
            outputString.append(destString)
            
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
        self.myDescription = outputString
    }
    
    var description: String {
        return myDescription
    }
/*    var makeDescription: String {
        var outputString = ""
        if self.deviceType == .asa {
            outputString.append("access-list 101 extended ")
        }
        if self.deviceType == .iosxr {
            let sequenceString = String(format: "%4d ", self.sequence)
            outputString.append(sequenceString)
        }
        outputString.append("\(aclAction) \(ipProtocol) ")
        switch self.deviceType {
        case .ios, .iosxr:
            outputString.append("\(self.sourceIp.ipv4) \(sourcePrefix.dontCareBits) ")
        case .asa:
            outputString.append("\(self.sourceIp.ipv4) \(sourcePrefix.netmask) ")
        case .nxos:
            outputString.append("\(self.sourceIp.ipv4)/\(sourcePrefix.rawValue) ")
        case .arista:
            fatalError("Not implemented")
        case .iosv6:
            outputString.append("\(sourceV6cidr) ")
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
        //outputString.append(" \(self.destIp.ipv4)")
        switch self.deviceType {
        case .ios, .iosxr:
            outputString.append(" \(self.destIp.ipv4) \(destPrefix.dontCareBits) ")
        case .asa:
            outputString.append(" \(self.destIp.ipv4) \(destPrefix.netmask) ")
        case .nxos:
            outputString.append(" \(self.destIp.ipv4)/\(destPrefix.rawValue) ")
        case .arista:
            fatalError("Not implemented")
        case .iosv6:
            outputString.append(" \(destV6cidr) ")

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
    }*/
    
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
