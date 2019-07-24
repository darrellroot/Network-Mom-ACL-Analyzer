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
    
    var aclAction: AclAction
    var ipProtocol: String
    var sourceIp: UInt
    var sourceDontCare: UInt
    let sourceLowPort: UInt
    let sourceHighPort: UInt
    var sourcePortOperator: PortOperator
    var destIp: UInt
    var destDontCare: UInt
    let destLowPort: UInt
    let destHighPort: UInt
    var destPortOperator: PortOperator
    
    init() {
        let sourceIp = UInt.random(in: 0...UInt(UInt32.max))
        self.sourceDontCare = RandomAcl.dontcareMasks.randomElement()!
        let sourceRemainder = sourceIp % sourceDontCare.dontCareHosts!
        self.sourceIp = sourceIp - sourceRemainder
        let destIp = UInt.random(in: 0...UInt(UInt32.max))
        self.destDontCare = RandomAcl.dontcareMasks.randomElement()!
        let destRemainder = destIp % destDontCare.dontCareHosts!
        self.destIp = destIp - destRemainder
        self.ipProtocol = RandomAcl.protocols.randomElement()!
        
        self.aclAction = [.permit,.deny].randomElement()!
        
        let port1 = UInt.random(in: 0...RandomAcl.maxport)
        let port2 = UInt.random(in: 0...RandomAcl.maxport)
        let port3 = UInt.random(in: 0...RandomAcl.maxport)
        let port4 = UInt.random(in: 0...RandomAcl.maxport)
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
        //self.sourcePortOperator = PortOperator.AllCases().randomElement()!
        self.destPortOperator = PortOperator.allCases.randomElement()!
        self.ipProtocol = RandomAcl.protocols.randomElement()!
    }
    
    var description: String {
        let sourceString = "\(aclAction) \(ipProtocol) \(sourceIp.ipv4) \(sourceDontCare.ipv4)"
        let sourcePortString: String
        let destPortString: String
        switch ipProtocol {
        case "tcp","udp","6","17":
            switch sourcePortOperator {
            case .eq,.gt,.lt:
                sourcePortString = "\(sourcePortOperator) \(sourceLowPort)"
            case .ne:
                sourcePortString = "neq \(sourceLowPort)"
            case .range:
                sourcePortString = "\(sourcePortOperator) \(sourceLowPort) \(sourceHighPort)"
//            case .nothing:
//                sourcePortString = ""
            }
            switch destPortOperator {
            case .eq,.gt,.lt:
                destPortString = "\(destPortOperator) \(destLowPort)"
            case .ne:
                destPortString = "neq \(destLowPort)"
            case .range:
                destPortString = "\(destPortOperator) \(destLowPort) \(destHighPort)"
//            case .nothing:
//                destPortString = ""
            }
        default:
            sourcePortString = ""
            destPortString = ""
        }
        let destString = "\(destIp.ipv4) \(destDontCare.ipv4)"
        let established: String
        switch ipProtocol {
        case "tcp","6":
            if Bool.random() {
                established = "established"
            } else {
                established = ""
            }
        default:
            established = ""
        }
        var log = ""
        if Bool.random() {
            log = "log"
        }
        let description = "\(sourceString) \(sourcePortString) \(destString) \(destPortString) \(established) \(log)\n"
        return description
    }
    
    
    static let maxip = UInt(UInt32.max)
    static let maxport = UInt(UInt16.max)
    
    static let dontcareMasks: [UInt] = [0,1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535,131071,262143,524287,1048575,2097151,4194303,8388607,16777215,33554431,67108863,134217727,268435455,536870911,1073741823,2147483647,4294967295]
    static let operators = ["eq","lt","gt","neq","range",""]
    
    static func ipv4String() -> String {
        let ipv4 = UInt.random(in: 0...UInt(UInt32.max))
        return ipv4.ipv4
    }
    static func dontcare() -> String {
        //let valid = Bool.random()
        let valid = true
        if valid {
            return dontcareMasks.randomElement()!.ipv4
        } else {
            return UInt.random(in: 0...UInt(UInt32.max)).ipv4
        }
    }
    static func operation() -> String {
        //let valid = Bool.random()
        let valid = true
        let portOperator = PortOperator.allCases.randomElement()!
        var portOperatorString: String = ""
        let port1 = UInt.random(in: 0...RandomAcl.maxport)
        let port2 = UInt.random(in: 0...RandomAcl.maxport)
        if valid {
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
//            case .nothing:
//                portOperatorString = ""
            }
        } else {
            if Bool.random() {
                portOperatorString += portOperator.rawValue
            }
            if Bool.random() {
                portOperatorString += " \(port1)"
            }
            if Bool.random() {
                portOperatorString += " \(port2)"
            }
        }
        return portOperatorString
    }
}
