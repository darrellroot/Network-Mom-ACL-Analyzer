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

        if let newFont = NSFont(name: "Consolas", size: 12) {
            fontManager.setSelectedFont(newFont, isMultiple: false)
        } else if let newFont = NSFont(name: "Courier", size: 12) {
            fontManager.setSelectedFont(newFont, isMultiple: false)
        }
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
        case "Random IPv4 IOS ACL":
            randomAclController.deviceType = .ios
        case "Random IPv4 IOS-XR ACL":
            randomAclController.deviceType = .iosxr
        case "Random IPv4 NX-OS ACL":
            randomAclController.deviceType = .nxos
        case "Random IPv4 ASA ACL":
            randomAclController.deviceType = .asa
        case "Random IPv6 IOS ACL":
            randomAclController.deviceType = .iosv6
        case "Random IPv6 IOS-XR ACL":
            randomAclController.deviceType = .iosxrv6
        case "Random IPv6 NX-OS ACL":
            randomAclController.deviceType = .nxosv6
        default:
            debugPrint("Fix appdelegate.randomAcl.switch sender.title")
        }
        self.randomAclControllers.append(randomAclController)
            randomAclController.showWindow(self)
        
    }
    
}

