//
//  AclDelegate.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/30/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

protocol AclDelegate {
    func getObjectGroupNetwork(_ group: String) -> ObjectGroupNetwork?
    func foundName(_ name: String)
}
