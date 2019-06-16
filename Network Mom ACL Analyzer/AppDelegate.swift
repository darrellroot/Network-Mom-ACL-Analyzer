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
    
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
        let analyzeDashboardController = AnalyzeDashboardController()
        analyzeDashboardControllers.append(analyzeDashboardController)
        analyzeDashboardController.showWindow(self)
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    @IBAction func newAclAnalyzer(_ sender: NSMenuItem) {
        let analyzeDashboardController = AnalyzeDashboardController()
        analyzeDashboardControllers.append(analyzeDashboardController)
        analyzeDashboardController.showWindow(self)
    }
}

