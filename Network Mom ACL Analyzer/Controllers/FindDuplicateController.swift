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
    
    @IBOutlet weak var validateButtonOutlet: NSButton!
    @IBOutlet weak var analyzeButtonOutlet: NSButton!
    @IBOutlet weak var cancelButtonOutlet: NSButton!
    @IBOutlet weak var progressBarOutlet: NSProgressIndicator!
    
    var fontManager: NSFontManager!
    
    var accessList: AccessList?
    var deviceType: DeviceType = .ios
    var outputTextString = ""
    var outputTimerActive = false
    var analysisRunning = false
    var cancelButtonPushed = false
    
    var totalCalculations = 0.0
    var currentCalculation = 0.0

    override func windowDidLoad() {
        super.windowDidLoad()
        /*aclTextView.substituteFontName = "Courier"
        outputTextView.substituteFontName = "Courier"*/
        self.progressBarOutlet.minValue = 0.0

        self.fontManager = NSFontManager.shared
        if let newFont = fontManager.selectedFont {
            aclTextView.font = newFont
            outputTextView.font = newFont
        }
        outputTextView.string = """
        To find "duplicate" ACL lines:
        1) Input your ACL in the top window
        2) Click "Validate ACLs and Search for Duplicates"
        
        Sample Output:
        
        line   256: deny 6 128.0.0.0 127.255.255.255 lt 26117 128.0.0.0 127.255.255.255 lt 50797 established
        line   574:     deny 6 248.64.0.0 0.15.255.255 eq 15355 227.45.128.0 0.0.127.255 eq 10432 established
        line   700:     deny tcp 175.195.108.0 0.0.1.255 eq 7213 148.0.0.0 3.255.255.255 lt 31335 established log
        line   769:     permit 6 232.160.0.0 0.7.255.255 lt 4482 204.69.76.0 0.0.0.255 eq 1546 established log
        
        The non-indented line "masks" the later (indented) lines.  The later lines could be said to be "duplicates".  But the first line could be too broad.  After all, every line is a "duplicate" of "permit ip any any".  You have to decide whether to remove the duplicate line or address the (possibly overbroad) "original" line.
        """
    }
    
    private func readyToValidate() -> Bool {
        self.outputTextString = ""
        self.outputTextView.string.removeAll()
        
        guard let deviceTypeString = deviceTypeOutlet.titleOfSelectedItem else {
            self.report(severity: .error, message: "Unable to identify ingress device type", delegateWindow: .duplicateOutput)
            return false
        }
        switch deviceTypeString {
        case "IOS or IOS-XE":
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
        self.progressBarOutlet.doubleValue = 0.0
        guard readyToValidate() else {
            return
        }
        let aclString = aclTextView.string

        self.disableButtons()
        
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
            DispatchQueue.main.async {
                self.enableButtons()
            }
        }
    }
    func disableButtons() {
        DispatchQueue.main.async {
            self.analysisRunning = true
            self.analyzeButtonOutlet.isEnabled = false
            self.validateButtonOutlet.isEnabled = false
            self.cancelButtonOutlet.isEnabled = true
            self.cancelButtonPushed = false
        }
    }
    func enableButtons() {
        DispatchQueue.main.async {
            self.analysisRunning = false
            self.outputTextView.string = self.outputTextString
            self.analyzeButtonOutlet.isEnabled = true
            self.validateButtonOutlet.isEnabled = true
            self.cancelButtonOutlet.isEnabled = false
            self.cancelButtonPushed = false
            self.progressBarOutlet.stopAnimation(self)
        }
    }
    
    @IBAction func cancelButton(_ sender: NSButton) {
        self.cancelButtonPushed = true
    }
    @IBAction func analyzeButton(_ sender: NSButton) {
        guard readyToValidate() else {
            return
        }
        let aclString = aclTextView.string
        
        self.disableButtons()
        
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
            let aclSize = accessList.accessControlEntries.count
            self.totalCalculations = Double(aclSize * (aclSize - 1) / 2)
            self.currentCalculation = 0.0
            DispatchQueue.main.async {
                self.progressBarOutlet.maxValue = self.totalCalculations
                self.progressBarOutlet.doubleValue = self.currentCalculation // 0.0
                self.progressBarOutlet.startAnimation(self)
            }
            var topPrinted = false
            var anyPrinted = false
            for topIndex in 0..<(accessList.accessControlEntries.count - 1) {
                DispatchQueue.main.async {
                    self.progressBarOutlet.doubleValue = self.currentCalculation
                }
                if self.cancelButtonPushed == true {
                    self.report(severity: .linetext, message: "    Analysis Incomplete (cancelled)",delegateWindow: .duplicateOutput)

                    break
                }

                for bottomIndex in (topIndex+1)..<accessList.accessControlEntries.count {
                    self.currentCalculation = self.currentCalculation + 1.0
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
        let lineString = String(format: "line %5d: \(message)", line)
        //self.report(severity: severity, message: "line \(line): \(message)", delegateWindow: delegateWindow)
        self.report(severity: severity, message: lineString, delegateWindow: delegateWindow)
    }
    
    func report(severity: Severity, message: String, delegateWindow: DelegateWindow?) {
        //debugPrint("report \(severity) \(message)")
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
        if !outputTimerActive && !analysisRunning {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
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
