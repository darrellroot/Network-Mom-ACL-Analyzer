//
//  AnalyzeDashboardController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class AnalyzeDashboardController: NSWindowController, NSWindowDelegate, NSTextViewDelegate, ErrorDelegate {
    
    let appDelegate = NSApplication.shared.delegate as! AppDelegate

    @IBOutlet var ingressAclTextView: NSTextView!
    @IBOutlet var egressAclTextView: NSTextView!
    @IBOutlet var ingressAclValidation: NSTextView!
    @IBOutlet var egressAclValidation: NSTextView!
    @IBOutlet var ingressAclAnalysis: NSTextView!
    @IBOutlet var egressAclAnalysis: NSTextView!

    @IBOutlet weak var importIngressButton: NSButton!
    @IBOutlet weak var importEgressButton: NSButton!
    @IBOutlet weak var validateButton: NSButton!
    @IBOutlet weak var analyzeButton: NSButton!
    
    var ingressValidationString: String = ""
    var egressValidationString: String = ""
    var ingressAnalyzeString: String = ""
    var egressAnalyzeString: String = ""
    var outputTimerActive = false
    
    
    @IBOutlet weak var protocolButton: NSPopUpButton!
    @IBOutlet weak var sourceIpOutlet: NSTextField!
    @IBOutlet weak var sourcePortOutlet: NSTextField!
    @IBOutlet weak var destinationIpOutlet: NSTextField!
    @IBOutlet weak var destinationPortOutlet: NSTextField!
    
    @IBOutlet weak var ingressDeviceTypeOutlet: NSPopUpButton!
    @IBOutlet weak var egressDeviceTypeOutlet: NSPopUpButton!
    
    var ingressAccessList: AccessList?
    var egressAccessList: AccessList?
    var ingressDeviceType: DeviceType = .ios
    var egressDeviceType: DeviceType = .ios
    var fontManager: NSFontManager!
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("AnalyzeDashboardController")
    }
    
    func windowWillClose(_ notification: Notification) {
    appDelegate.analyzeDashboardControllers.remove(object: self)
    }

    override func windowDidLoad() {
        super.windowDidLoad()
        
        /*ingressAclTextView.substituteFontName = "Courier"
        egressAclTextView.substituteFontName = "Courier"
        ingressAclValidation.substituteFontName = "Courier"
        egressAclValidation.substituteFontName = "Courier"
        ingressAclAnalysis.substituteFontName = "Courier"
        egressAclAnalysis.substituteFontName = "Courier"*/

        self.fontManager = NSFontManager.shared
        if let newFont = fontManager.selectedFont {
            ingressAclTextView.font = newFont
            egressAclTextView.font = newFont
            ingressAclValidation.font = newFont
            egressAclValidation.font = newFont
            ingressAclAnalysis.font = newFont
            egressAclAnalysis.font = newFont
        }
        
        ingressAclValidation.string = """
        To validate ACL syntax:
        1) Input the ACL in the top-left text field.
        2) Select the type of device
        3) Click Validate
        
        Warning: Different variants of IOS/IOS-XR/ASA/NX-OS support different named ports, named protocols, object-group syntax, or sequence numbers.  This tool generally accepts a superset of those features.  Your device may not recognize some of those features.  Always watch for errors when pushing to production devices.
        """
        
        ingressAclAnalysis.string = """
        To determine if a specific TCP or UDP socket is permitted by an ACL:
        1) Input the ACL i the top-left text field.
        2) Select the type of device.
        3) Click Validate ACLs and Analyze Socket
        4) Make sure to review the validation window for errors.  ACL lines with errors are not included in the permit/deny analysis.
        
        Warning: This tool is not perfect.  Do not base your security decisions solely on the output of this tool.  If you find an error please email feedback@networkmom.net an ACL sample.
        """
        
        egressAclValidation.string = """
        Almost all network communications are bidirectional.  The "ingress" traffic (from the socket-initiator to the listening server) is analyzed against the ACL in the top-left window.  If you have a stateless "egress" ACL, place it in the top-right window.  The analyzer will automatically reverse the socket (including adding the "established" flag if TCP) and analyze the return direction.
        
        Adaptive Security Appliances (ASA's) are stateful firewalls and automatically permit return traffic as long as traffic in both directions traverses the same ASA device.
        """
        //ingressAclAnalysis.needsDisplay = true
        //ingressAclAnalysis.needsDisplay = true

    }
    
    @objc public func changeFont(sender: AnyObject) {
        guard let sender = sender as? NSFontManager else {
            return
        }
        guard let oldFont = ingressAclTextView.font else {
            return
        }
        let newFont = sender.convert(oldFont)
        ingressAclTextView.font = newFont
        egressAclTextView.font = newFont
        ingressAclValidation.font = newFont
        egressAclValidation.font = newFont
        ingressAclAnalysis.font = newFont
        egressAclAnalysis.font = newFont
    }
    
    @IBAction func importIngressButton(_ sender: NSButton) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.beginSheetModal(for: self.window!) { (result) in
            if result == .OK, let url = openPanel.url {
                debugPrint(url)
                if let newAcl =  try? String(contentsOf: url) {
                    self.ingressAclTextView.string = newAcl
                }
            }
        }
    }
    
    @IBAction func importEgressButton(_ sender: NSButton) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = false
        openPanel.canChooseDirectories = false
        openPanel.canCreateDirectories = false
        openPanel.canChooseFiles = true
        openPanel.beginSheetModal(for: self.window!) { (result) in
            if result == .OK, let url = openPanel.url {
                debugPrint(url)
                if let newAcl =  try? String(contentsOf: url) {
                    self.egressAclTextView.string = newAcl
                }
            }
        }
    }
    
    private func validateSocket() -> Socket? {
        let ipProtocol = UInt(protocolButton.selectedTag())
        guard ipProtocol < 256 else {
            self.report(severity: .error, message: "Socket: Invalid IP Protocol", delegateWindow: .ingressAnalyze)
            return nil
        }
        guard let sourceIp = sourceIpOutlet.stringValue.ipv4address else {
            self.report(severity: .error, message: "Socket: Invalid source IPv4 address", delegateWindow: .ingressAnalyze)
            return nil
        }
        if sourcePortOutlet.stringValue.isEmpty {
            let number = UInt.random(in: 1024 ... 65535)
            sourcePortOutlet.stringValue = "\(number)"
        }
        guard let sourcePort16 = UInt16(sourcePortOutlet.stringValue) else {
            self.report(severity: .error, message: "Socket: Invalid source port", delegateWindow: .ingressAnalyze)
            return nil
        }
        let sourcePort = UInt(sourcePort16)
        guard let destinationIp = destinationIpOutlet.stringValue.ipv4address else {
            self.report(severity: .error, message: "Socket: Invalid destination IPv4 address", delegateWindow: .ingressAnalyze)
            return nil
        }
        guard let destinationPort16 = UInt16(destinationPortOutlet.stringValue) else {
            self.report(severity: .error, message: "Socket: Invalid destination port", delegateWindow: .ingressAnalyze)
            return nil
        }
        let destinationPort = UInt(destinationPort16)
        guard let socket = Socket(ipProtocol: ipProtocol, sourceIp: sourceIp, destinationIp: destinationIp, sourcePort: sourcePort, destinationPort: destinationPort, established: false) else {
            self.report(severity: .error, message: "Unable to specify socket with current configuration", delegateWindow: .ingressAnalyze)
            return nil
        }
        self.report(severity: .notification, message: "Socket configured: \(socket)", delegateWindow: .ingressAnalyze)
        return socket
    }
    private func readyToValidate() -> Bool {
        
        self.ingressValidationString = ""
        self.egressValidationString = ""
        self.ingressAnalyzeString = ""
        self.egressAnalyzeString = ""
        self.ingressAclValidation.string.removeAll()
        self.egressAclValidation.string.removeAll()
        self.ingressAclAnalysis.string.removeAll()
        self.egressAclAnalysis.string.removeAll()

        guard let ingressDeviceTypeString = ingressDeviceTypeOutlet.titleOfSelectedItem else {
            self.report(severity: .error, message: "Unable to identify ingress device type", delegateWindow: .ingressValidation)
            return false
        }
        guard let egressDeviceTypeString = egressDeviceTypeOutlet.titleOfSelectedItem else {
            self.report(severity: .error, message: "Unable to identify egress device type", delegateWindow: .ingressValidation)
            return false
        }
        switch ingressDeviceTypeString {
        case "IOS":
            self.ingressDeviceType = .ios
        case "IOS-XR":
            self.ingressDeviceType = .iosxr
        case "ASA":
            self.ingressDeviceType = .asa
        case "NX-OS":
            self.ingressDeviceType = .nxos
        case "Arista":
            self.ingressDeviceType = .arista
        default:
            self.report(severity: .error, message: "Unable to identify ingress device type", delegateWindow: .ingressValidation)
            return false
        }
        switch egressDeviceTypeString {
        case "IOS":
            self.egressDeviceType = .ios
        case "IOS-XR":
            self.egressDeviceType = .iosxr
        case "NX-OS":
            self.egressDeviceType = .nxos
        case "Arista":
            self.egressDeviceType = .arista
        default:
            self.report(severity: .error, message: "Unable to identify egress device type", delegateWindow: .egressValidation)
            return false
        }
        return true
    }
    @IBAction func validateAcl(_ sender: Any) {

        guard readyToValidate() else {
            return
        }
        
        self.disableButtons()

        let ingressString = ingressAclTextView.string
        let egressString = egressAclTextView.string
        
        DispatchQueue.global(qos: .background).async {
            self.ingressAccessList = AccessList(sourceText: ingressString, deviceType: self.ingressDeviceType, delegate: self, delegateWindow: .ingressValidation)
            self.egressAccessList = AccessList(sourceText: egressString, deviceType: self.egressDeviceType, delegate: self, delegateWindow: .egressValidation)
            if self.ingressAccessList?.count == 0 {
                self.ingressAccessList = nil
            }
            if self.egressAccessList?.count == 0 {
                self.egressAccessList = nil
            }
            if let ingressAccessList = self.ingressAccessList {
                self.report(severity: .warning, message: "Analyzed \(ingressAccessList.count) Access Control Entries.  ACL Name \(ingressAccessList.aclNames)", delegateWindow: .ingressValidation)
                for warning in ingressAccessList.warnings {
                    self.report(severity: .warning, message: warning, delegateWindow: .ingressValidation)
                }
            } else {
                self.report(severity: .warning, message: "Ingress Access List Not Analyzed", delegateWindow: .ingressValidation)
            }
            if let egressAccessList = self.egressAccessList {
                self.report(severity: .warning, message: "Analyzed \(egressAccessList.count) Access Control Entries.  ACL Name \(egressAccessList.aclNames)", delegateWindow: .egressValidation)
                for warning in egressAccessList.warnings {
                    self.report(severity: .warning, message: warning, delegateWindow: .egressValidation)
                }
            } else {
                self.report(severity: .warning, message: "Egress Access List Not Analyzed", delegateWindow: .egressValidation)
            }
            DispatchQueue.main.async {
                self.enableButtons()
            }
        }
    }
    
    @IBAction func analyzeButton(_ sender: NSButton) {
        
        guard readyToValidate() else {
            return
        }
        guard let ingressSocket = validateSocket() else {
            return
        }
        
        self.disableButtons()

        let ingressString = self.ingressAclTextView.string
        let egressString = self.egressAclTextView.string

        DispatchQueue.global(qos: .background).async {
            self.ingressAccessList = AccessList(sourceText: ingressString, deviceType: self.ingressDeviceType, delegate: self, delegateWindow: .ingressValidation)
            self.egressAccessList = AccessList(sourceText: egressString, deviceType: self.egressDeviceType, delegate: self, delegateWindow: .egressValidation)
            if self.ingressAccessList?.count == 0 {
                self.ingressAccessList = nil
            }
            if self.egressAccessList?.count == 0 {
                self.egressAccessList = nil
            }
            if let ingressAccessList = self.ingressAccessList {
                self.report(severity: .warning, message: "Analyzed \(ingressAccessList.count) Access Control Entries.  ACL Name \(ingressAccessList.aclNames)", delegateWindow: .ingressValidation)
                _ = self.ingressAccessList?.analyze(socket: ingressSocket, errorDelegate: self, delegateWindow: .ingressAnalyze)
            } else {
                self.report(severity: .warning, message: "Ingress Access List Not Analyzed", delegateWindow: .ingressValidation)
            }
            if let egressAccessList = self.egressAccessList {
                self.report(severity: .warning, message: "Analyzed \(egressAccessList.count) Access Control Entries.  ACL Name \(egressAccessList.aclNames)", delegateWindow: .egressValidation)
                if let egressSocket = ingressSocket.reverse() {
                    self.report(severity: .notification, message: "Socket configured: \(egressSocket)", delegateWindow: .egressAnalyze)
                    _ = self.egressAccessList?.analyze(socket: egressSocket, errorDelegate: self, delegateWindow: .egressAnalyze)
                } else {
                    self.report(severity: .error, message: "Unable to generate egress socket", delegateWindow: .egressAnalyze)
                }
            } else {
                self.report(severity: .warning, message: "Egress Access List Not Analyzed", delegateWindow: .egressValidation)
            }
            DispatchQueue.main.async {
                self.enableButtons()
            }
        }
    }

    private func disableButtons() {
        DispatchQueue.main.async {
            self.importIngressButton.isEnabled = false
            self.importEgressButton.isEnabled = false
            self.validateButton.isEnabled = false
            self.analyzeButton.isEnabled = false
        }
    }
    private func enableButtons() {
        DispatchQueue.main.async {
            self.importIngressButton.isEnabled = true
            self.importEgressButton.isEnabled = true
            self.validateButton.isEnabled = true
            self.analyzeButton.isEnabled = true
        }
    }

    func report(severity: Severity, message: String, line: Int, delegateWindow: DelegateWindow?) {
        self.report(severity: severity, message: "line \(line): \(message)", delegateWindow: delegateWindow)
    }
    
    func report(severity: Severity, message: String, delegateWindow: DelegateWindow?) {
        guard let delegateWindow = delegateWindow else {
            return
        }
        var severityText = "\(severity) "
        if severity == .linetext {
            severityText = ""
        }
        switch delegateWindow {
        case .duplicateOutput:
            debugPrint("Invalid delegate window \(delegateWindow) for AnalyzeDashboardController")
        case .ingressValidation:
            ingressValidationString.append(contentsOf: "\(severityText)\(message)\n")
        case .egressValidation:
            egressValidationString.append(contentsOf: "\(severityText)\(message)\n")
        case .ingressAnalyze:
            ingressAnalyzeString.append(contentsOf: "\(severityText)\(message)\n")
        case .egressAnalyze:
            egressAnalyzeString.append(contentsOf: "\(severityText)\(message)\n")
        }
        if !outputTimerActive {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                self.ingressAclValidation.string = self.ingressValidationString
                self.egressAclValidation.string = self.egressValidationString
                self.ingressAclAnalysis.string = self.ingressAnalyzeString
                self.egressAclAnalysis.string = self.egressAnalyzeString
                self.outputTimerActive = false
            }
            outputTimerActive = true
        }
    }
}
