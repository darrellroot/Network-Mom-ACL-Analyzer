//
//  RandomAclController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/24/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class RandomAclController: NSWindowController {
    
    let appDelegate = NSApplication.shared.delegate as! AppDelegate
    
    @IBOutlet var aclTextView: NSTextView!
    var aclString = "! WARNING: DO NOT USE RANDOM ACLS IN PRODUCTION ENVIRONMENTS\n"
    var deviceType: DeviceType? = nil  // set by AppDelegate when called
    
    override func windowDidLoad() {
        super.windowDidLoad()
        
        aclTextView.substituteFontName = "Consolas"

        guard let deviceType = deviceType else {
            aclString = "ERROR: UNKNOWN DEVICE TYPE"
            return
        }
        switch deviceType {
        case .ios:
            self.window?.title = "Random IOS ACL"
        case .asa:
            self.window?.title = "Random ASA ACL"
        case .nxos:
            self.window?.title = "Random NX-OS ACL"
        case .iosxr:
            self.window?.title = "Random IOS-XR ACL"
        case .arista:
            self.window?.title = "Random Arista ACL"
        }
        RandomAcl.staticSequence = 1
        for _ in 0..<1000 {
            let ace = RandomAcl(deviceType: deviceType)
            aclString.append(ace.description)
        }
        aclString.append("! WARNING: DO NOT USE RANDOM ACLS IN PRODUCTION ENVIRONMENTS\n")
        aclTextView.string = aclString
        
        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("RandomAclController")
    }
    
    func windowWillClose(_ notification: Notification) {
        appDelegate.randomAclControllers.remove(object: self)
    }

}
