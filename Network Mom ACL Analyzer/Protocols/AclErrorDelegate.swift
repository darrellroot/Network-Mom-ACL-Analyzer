//
//  AclErrorReporting.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

protocol AclErrorDelegate {
    func report(severity: Severity, message: String, line: Int)
    func report(severity: Severity, message: String)
}
