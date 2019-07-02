//
//  PrivacyPolicyController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/20/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class PrivacyPolicyController: NSWindowController {

    @IBOutlet var privacyTextViewOutlet: NSTextView!
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("PrivacyPolicyController")
    }

    override func windowDidLoad() {
        super.windowDidLoad()
        if let path = Bundle.main.path(forResource: "PrivacyPolicy", ofType: "rtfd") {
            _ = privacyTextViewOutlet.readRTFD(fromFile: path)
        }
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
}
