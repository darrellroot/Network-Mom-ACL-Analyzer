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

    let expirationDateComponents = DateComponents(calendar: Calendar.current, timeZone: .current, era: nil, year: 2019, month: 8, day: 1, hour: 1, minute: 1, second: 1, nanosecond: nil, weekday: nil, weekdayOrdinal: nil, quarter: nil, weekOfMonth: nil, weekOfYear: nil, yearForWeekOfYear: nil)
    var analyzeDashboardControllers: [AnalyzeDashboardController] = []
    var fontManager: NSFontManager!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        
        self.fontManager = NSFontManager.shared
        fontManager.target = self
        fontManager.action = #selector(self.changeFont(sender:))

        let analyzeDashboardController = AnalyzeDashboardController()
    analyzeDashboardControllers.append(analyzeDashboardController)
    analyzeDashboardController.showWindow(self)
        
        /*let expirationDate = Calendar.current.nextDate(after: Date(timeIntervalSinceReferenceDate: 0), matching: expirationDateComponents, matchingPolicy: .nextTime)
        
        if let expirationDate = expirationDate, expirationDate > Date() {
            let analyzeDashboardController = AnalyzeDashboardController()
            analyzeDashboardControllers.append(analyzeDashboardController)
            analyzeDashboardController.showWindow(self)
        } else {
            expiredAlert()
        }*/
        
    //NSApplication.shared.orderFrontStandardAboutPanel(self)

    }

    @objc public func changeFont(sender: AnyObject) {
        for analyzeDashboardController in analyzeDashboardControllers {
            analyzeDashboardController.changeFont(sender: sender)
        }
    }
    
    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    @IBAction func privacyPolicy(_ sender: NSMenuItem) {
        let privacyPolicyController = PrivacyPolicyController()
        privacyPolicyController.showWindow(self)
    }
    @IBAction func helpMenu(_ sender: NSMenuItem) {
        let helpController = HelpController()
        helpController.showWindow(self)
    }

    @IBAction func newAclAnalyzer(_ sender: NSMenuItem) {
        let expirationDate = Calendar.current.nextDate(after: Date(timeIntervalSinceReferenceDate: 0), matching: expirationDateComponents, matchingPolicy: .nextTime)
        if let expirationDate = expirationDate, expirationDate > Date() {
            let analyzeDashboardController = AnalyzeDashboardController()
            analyzeDashboardControllers.append(analyzeDashboardController)
            analyzeDashboardController.showWindow(self)
        } else {
            expiredAlert()
        }
    }
    func expiredAlert() {
        let alert = NSAlert()
        alert.messageText = "This early alpha version of Network Mom ACL Analyzer has expired"
        alert.informativeText = "Go to https://networkmom.net/acl or (eventually) the MacOS 10.14 Mojave or MacOS 10.15 Catalina app store"
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

