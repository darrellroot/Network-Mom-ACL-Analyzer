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

    var inputAccessListControllers: [InputAccessListController] = []

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    @IBAction func inputAccessList(_ sender: NSMenuItem) {
        let inputAccessListController = InputAccessListController()
        inputAccessListControllers.append(inputAccessListController)
        inputAccessListController.showWindow(self)
    }
    
}

