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
        
        self.fontManager = NSFontManager.shared
        if let newFont = fontManager.selectedFont {
            ingressAclTextView.font = newFont
            egressAclTextView.font = newFont
            ingressAclValidation.font = newFont
            egressAclValidation.font = newFont
            ingressAclAnalysis.font = newFont
            egressAclAnalysis.font = newFont
        }
        //fontManager.target = self
        //fontManager.action = #selector(self.changeFont(sender:))
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
        
        /*
         let oldAttributes = ingressAclTextView.typingAttributes
         var transitionAttributes: [String:Any] = [:]
         for attribute in oldAttributes {
         transitionAttributes[attribute.key.rawValue] = attribute.value
         }
         let newAttributes = sender.convertAttributes(transitionAttributes)
        var finalAttributes: [NSAttributedString.Key : Any] = [:]
        
        for attribute in newAttributes {
            let attributeKey = NSAttributedString.Key(attribute.key)
            finalAttributes[attributeKey] = attribute.value
        }
        ingressAclTextView.typingAttributes = finalAttributes
        egressAclTextView.typingAttributes = finalAttributes
        ingressAclValidation.typingAttributes = finalAttributes
        egressAclValidation.typingAttributes = finalAttributes
        ingressAclAnalysis.typingAttributes = finalAttributes
        egressAclAnalysis.typingAttributes = finalAttributes*/
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
        ingressAclValidation.string.removeAll()
        egressAclValidation.string.removeAll()
        
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
        case "ASA":
            self.ingressDeviceType = .asa
        default:
            self.report(severity: .error, message: "Unable to identify ingress device type", delegateWindow: .ingressValidation)
            return false
        }
        switch egressDeviceTypeString {
        case "IOS":
            self.egressDeviceType = .ios
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
            DispatchQueue.main.async {
                if let ingressAccessList = self.ingressAccessList {
                    self.ingressAclValidation.string.append("Analyzed \(ingressAccessList.count) Access Control Entries.  ACL Name \(ingressAccessList.names)")
                } else {
                    self.ingressAclValidation.string.append("Ingress Access List Not Analyzed")
                }
                if let egressAccessList = self.egressAccessList {
                    self.egressAclValidation.string.append("Analyzed \(egressAccessList.count) Access Control Entries.  ACL Name \(egressAccessList.names)")
                } else {
                    self.egressAclValidation.string.append("Egress Access List Not Analyzed")
                }
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
        
        ingressAclAnalysis.string = ""
        egressAclAnalysis.string = ""
        let ingressString = self.ingressAclTextView.string

        DispatchQueue.global(qos: .background).async {

            self.ingressAccessList = AccessList(sourceText: ingressString, deviceType: self.ingressDeviceType, delegate: self, delegateWindow: .ingressValidation)
            if self.ingressAccessList?.count == 0 {
                self.ingressAccessList = nil
            }
            _ = self.ingressAccessList?.analyze(socket: ingressSocket, errorDelegate: self, delegateWindow: .ingressAnalyze)
        }
        
        guard let egressSocket = ingressSocket.reverse() else {
            self.report(severity: .error, message: "Unable to generate egress socket", delegateWindow: .egressAnalyze)
            return
        }
        self.report(severity: .notification, message: "Socket configured: \(egressSocket)", delegateWindow: .egressAnalyze)
        let egressString = self.egressAclTextView.string
        DispatchQueue.global(qos: .background).async {
            self.egressAccessList = AccessList(sourceText: egressString, deviceType: self.egressDeviceType, delegate: self, delegateWindow: .egressValidation)
            if self.egressAccessList?.count == 0 {
                self.egressAccessList = nil
            }
            _ = self.egressAccessList?.analyze(socket: egressSocket, errorDelegate: self, delegateWindow: .egressAnalyze)
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
        DispatchQueue.main.async {
            switch delegateWindow {
            case .ingressValidation:
                self.ingressAclValidation.string.append(contentsOf: "\(severityText)\(message)\n")
            case .egressValidation:
                self.egressAclValidation.string.append(contentsOf: "\(severityText)\(message)\n")
            case .ingressAnalyze:
                self.ingressAclAnalysis.string.append(contentsOf: "\(severityText)\(message)\n")
            case .egressAnalyze:
                self.egressAclAnalysis.string.append(contentsOf: "\(severityText)\(message)\n")
            }
        }
    }
}
