//
//  InputAccessListController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class InputAccessListController: NSWindowController, NSWindowDelegate {

    @IBOutlet var accessListInput: NSTextView!
    
    let appDelegate = NSApplication.shared.delegate as! AppDelegate

    override var windowNibName: NSNib.Name? {
        return NSNib.Name("InputAccessListController")
    }

    override func windowDidLoad() {
        super.windowDidLoad()
        window?.toolbar?.isVisible = false
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    func windowWillClose(_ notification: Notification) {
        appDelegate.inputAccessListControllers.remove(object: self)
    }
    @IBAction func validate(_ sender: NSButton) {
        let accessList = AccessList(sourceText: accessListInput.string)
    }
}
