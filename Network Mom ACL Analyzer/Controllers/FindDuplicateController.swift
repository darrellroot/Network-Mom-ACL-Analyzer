//
//  FindDuplicateController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/23/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class FindDuplicateController: NSWindowController, ErrorDelegate {
    

    let appDelegate = NSApplication.shared.delegate as! AppDelegate

    @IBOutlet weak var deviceTypeOutlet: NSPopUpButton!
    @IBOutlet var aclTextView: NSTextView!
    @IBOutlet var outputTextView: NSTextView!
    
    var fontManager: NSFontManager!
    
    var accessList: AccessList?
    var deviceType: DeviceType = .ios
    var outputTextString = ""
    var outputTimerActive = false

    override func windowDidLoad() {
        super.windowDidLoad()
        self.fontManager = NSFontManager.shared
        if let newFont = fontManager.selectedFont {
            aclTextView.font = newFont
            outputTextView.font = newFont
        }
    }
    
    private func readyToValidate() -> Bool {
        self.outputTextString = ""
        self.outputTextView.string.removeAll()
        
        guard let deviceTypeString = deviceTypeOutlet.titleOfSelectedItem else {
            self.report(severity: .error, message: "Unable to identify ingress device type", delegateWindow: .duplicateOutput)
            return false
        }
        switch deviceTypeString {
        case "IOS":
            self.deviceType = .ios
        case "IOS-XR":
            self.deviceType = .iosxr
        case "ASA":
            self.deviceType = .asa
        case "NX-OS":
            self.deviceType = .nxos
        case "Arista":
            self.deviceType = .arista
        default:
            self.report(severity: .error, message: "Unable to identify device type", delegateWindow: .duplicateOutput)
            return false
        }
        return true
    }
    
    @IBAction func validateButton(_ sender: NSButton) {
        guard readyToValidate() else {
            return
        }
        let aclString = aclTextView.string

        //TODO
        //self.disableButtons()
        
        DispatchQueue.global(qos: .background).async {
            self.accessList = AccessList(sourceText: aclString, deviceType: self.deviceType, delegate: self, delegateWindow: .duplicateOutput)
            if self.accessList?.count == 0 {
                self.accessList = nil
            }
            if let accessList = self.accessList {
                self.report(severity: .warning, message: "Analyzed \(accessList.count) Access Control Entries.  ACL Name \(accessList.aclNames)", delegateWindow: .duplicateOutput)
                for warning in accessList.warnings {
                    self.report(severity: .warning, message: warning, delegateWindow: .duplicateOutput)
                }
            } else {
                self.report(severity: .warning, message: "Access List Not Analyzed", delegateWindow: .duplicateOutput)
            }
            /* TODO
            DispatchQueue.main.async {
                self.enableButtons()
            }*/
        }
    }
    func disableButtons() {
        DispatchQueue.main.async {
            //TODO add functionality on main thread
        }
    }
    func enableButtons() {
        DispatchQueue.main.async {
            //TODO add functionality on main thread
        }
    }
    
    @IBAction func analyzeButton(_ sender: NSButton) {
        guard readyToValidate() else {
            return
        }
        let aclString = aclTextView.string
        
        //self.disableButtons()
        
        DispatchQueue.global(qos: .background).async {
            self.accessList = AccessList(sourceText: aclString, deviceType: self.deviceType, delegate: self, delegateWindow: .duplicateOutput)
            if self.accessList?.count == 0 {
                self.accessList = nil
            }
            guard let accessList = self.accessList else {
                self.report(severity: .warning, message: "Access List Not Analyzed", delegateWindow: .duplicateOutput)
                self.enableButtons()
                return
            }
            self.report(severity: .warning, message: "Analyzed \(accessList.count) Access Control Entries.  ACL Name \(accessList.aclNames)", delegateWindow: .duplicateOutput)
            for warning in accessList.warnings {
                self.report(severity: .warning, message: warning, delegateWindow: .duplicateOutput)
            }

            guard accessList.accessControlEntries.count > 1 else {
                self.enableButtons()
                return
            }
            var topPrinted = false
            var anyPrinted = false
            for topIndex in 0..<(accessList.accessControlEntries.count - 1) {
                for bottomIndex in (topIndex+1)..<accessList.accessControlEntries.count {
                    let topAce = accessList.accessControlEntries[topIndex]
                    let bottomAce = accessList.accessControlEntries[bottomIndex]
                    if bottomAce.isDuplicate(of: topAce) {
                        if topPrinted == false {
                            self.report(severity: .linetext, message: "\(topAce.line)", line: topAce.linenum, delegateWindow: .duplicateOutput)
                            topPrinted = true
                        }
                        anyPrinted = true
                        self.report(severity: .linetext, message: "    \(bottomAce.line)", line: bottomAce.linenum, delegateWindow: .duplicateOutput)
                    }
                } // for bottomIndex
                if anyPrinted {
                    self.report(severity: .blank, message: "", delegateWindow: .duplicateOutput)
                }
                topPrinted = false
                anyPrinted = false
            } // for topIndex
            self.enableButtons()
        }
    }
    
    func report(severity: Severity, message: String, line: Int, delegateWindow: DelegateWindow?) {
        self.report(severity: severity, message: "line \(line): \(message)", delegateWindow: delegateWindow)
    }
    
    func report(severity: Severity, message: String, delegateWindow: DelegateWindow?) {
        debugPrint("report \(severity) \(message)")
        guard let delegateWindow = delegateWindow else {
            return
        }
        var severityText = "\(severity) "
        if severity == .linetext || severity == .blank {
            severityText = ""
        }
        switch delegateWindow {
        case .ingressAnalyze,.ingressValidation,.egressAnalyze,.egressValidation:
            debugPrint("Invalid delegate window \(delegateWindow) for FindDuplicateController")
            return
        case .duplicateOutput:
            outputTextString.append(contentsOf: "\(severityText)\(message)\n")
        }
        if !outputTimerActive {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                self.outputTextView.string = self.outputTextString
                self.outputTimerActive = false
            }
            outputTimerActive = true
        }
    }
    
    @objc public func changeFont(sender: AnyObject) {
        guard let sender = sender as? NSFontManager else {
            return
        }
        guard let oldFont = aclTextView.font else {
            return
        }
        let newFont = sender.convert(oldFont)
        aclTextView.font = newFont
        outputTextView.font = newFont
    }
    
    @IBAction func importFromFile(_ sender: NSButton) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.beginSheetModal(for: self.window!) { (result) in
            if result == .OK, let url = openPanel.url {
                debugPrint(url)
                if let newAcl =  try? String(contentsOf: url) {
                    self.aclTextView.string = newAcl
                }
            }
        }
    }
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("FindDuplicateController")
    }
    
    func windowWillClose(_ notification: Notification) {
        appDelegate.findDuplicateControllers.remove(object: self)
    }

}
