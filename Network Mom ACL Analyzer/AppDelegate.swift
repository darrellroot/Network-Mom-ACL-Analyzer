//
//  AppDelegate.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    var analyzeDashboardControllers: [AnalyzeDashboardController] = []
    var findDuplicateControllers:
    [FindDuplicateController] = []
    var randomAclControllers: [RandomAclController] = []

    var fontManager: NSFontManager!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        
        self.fontManager = NSFontManager.shared
        fontManager.target = self
        fontManager.action = #selector(self.changeFont(sender:))

        /*let analyzeDashboardController = AnalyzeDashboardController()
        analyzeDashboardControllers.append(analyzeDashboardController)
        analyzeDashboardController.showWindow(self)*/
    }

    @objc public func changeFont(sender: AnyObject) {
        for analyzeDashboardController in analyzeDashboardControllers {
            analyzeDashboardController.changeFont(sender: sender)
        }
        for findDuplicateController in findDuplicateControllers {
            findDuplicateController.changeFont(sender: sender)
        }
        for randomAclController in randomAclControllers {
            randomAclController.changeFont(sender: sender)
        }
    }
    
    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    @IBAction func newAclAnalyzer(_ sender: NSMenuItem) {
        let analyzeDashboardController = AnalyzeDashboardController()
        self.analyzeDashboardControllers.append(analyzeDashboardController)
        analyzeDashboardController.showWindow(self)
    }
    
    @IBAction func findDuplicateACLs(_ sender: NSMenuItem) {
        let findDuplicateController = FindDuplicateController()
        self.findDuplicateControllers.append(findDuplicateController)
        findDuplicateController.showWindow(self)
    }
    
    @IBAction func randomAcl(_ sender: NSMenuItem) {
        let randomAclController = RandomAclController()
        switch sender.title {
        case "Random IOS ACL":
            randomAclController.deviceType = .ios
        case "Random IOS-XR ACL":
            randomAclController.deviceType = .iosxr
        case "Random NX-OS ACL":
            randomAclController.deviceType = .nxos
        case "Random ASA ACL":
            randomAclController.deviceType = .asa
        default:
            debugPrint("Fix appdelegate.randomAcl.switch sender.title")
        }
        self.randomAclControllers.append(randomAclController)
            randomAclController.showWindow(self)
        
    }
    
}

