//
//  AnalyzeDashboardController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class AnalyzeDashboardController: NSWindowController, AclErrorDelegate {
    enum ActiveWarningWindow {
        case ingressValidation
        case egressValidation
    }

    @IBOutlet var ingressAclTextView: NSTextView!
    @IBOutlet var egressAclTextView: NSTextView!
    @IBOutlet var ingressAclValidation: NSTextView!
    @IBOutlet var egressAclValidation: NSTextView!
    
    var ingressAccessList: AccessList?
    var egressAccessList: AccessList?
    var activeWarningWindow: ActiveWarningWindow?
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("AnalyzeDashboardController")
    }

    override func windowDidLoad() {
        super.windowDidLoad()

        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    @IBAction func validateAcl(_ sender: NSButton) {
        ingressAclValidation.string = ""
        egressAclValidation.string = ""
        let ingressString = ingressAclTextView.string
        let egressString = egressAclTextView.string
        activeWarningWindow = .ingressValidation
        ingressAccessList = AccessList(sourceText: ingressString, delegate: self)
        activeWarningWindow = .egressValidation
        egressAccessList = AccessList(sourceText: egressString, delegate: self)
        activeWarningWindow = nil
        if egressAccessList?.count == 0 {
            egressAccessList = nil
        }
        if ingressAccessList?.count == 0 {
            ingressAccessList = nil
        }
        debugPrint("ingress access list count \(ingressAccessList?.count)")
        debugPrint("egress access list count \(egressAccessList?.count)")

    }
    func report(severity: Severity, message: String, line: Int) {
        guard let activeWarningWindow = activeWarningWindow else {
            debugPrint("No active warning window for message \(severity) \(message) \(line)")
            return
        }
        switch activeWarningWindow {
        case .ingressValidation:
            ingressAclValidation.string.append(contentsOf: "\(severity) line \(line) \(message)\n")
        case .egressValidation:
            egressAclValidation.string.append(contentsOf: "\(severity) line \(line) \(message)\n")
        }
    }
    func report(severity: Severity, message: String) {
        guard let activeWarningWindow = activeWarningWindow else {
            debugPrint("No active warning window for message \(severity) \(message)")
            return
        }
        switch activeWarningWindow {
        case .ingressValidation:
            ingressAclValidation.string.append(contentsOf: "\(severity) \(message)\n")
        case .egressValidation:
            egressAclValidation.string.append(contentsOf: "\(severity) \(message)\n")
        }
    }
}
