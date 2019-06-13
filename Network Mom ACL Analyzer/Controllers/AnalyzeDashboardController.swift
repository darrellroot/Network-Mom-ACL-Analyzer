//
//  AnalyzeDashboardController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class AnalyzeDashboardController: NSWindowController {

    @IBOutlet var ingressAclTextView: NSTextView!
    @IBOutlet var egressAclTextView: NSTextView!
    @IBOutlet var ingressAclValidation: NSTextView!
    @IBOutlet var egressAclValidation: NSTextView!
    
    var ingressAccessList: AccessList?
    var egressAccessList: AccessList?
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("AnalyzeDashboardController")
    }

    override func windowDidLoad() {
        super.windowDidLoad()

        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    @IBAction func validateAcl(_ sender: NSButton) {
        let ingressString = ingressAclTextView.string
        let egressString = ingressAclTextView.string
        ingressAccessList = AccessList(sourceText: ingressString)
        egressAccessList = AccessList(sourceText: egressString)
        if egressAccessList?.count == 0 {
            egressAccessList = nil
        }
        if ingressAccessList?.count == 0 {
            ingressAccessList = nil
        }
        debugPrint("ingress access list count \(ingressAccessList?.count)")
        debugPrint("egress access list count \(egressAccessList?.count)")

    }
}
