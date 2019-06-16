//
//  AnalyzeDashboardController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class AnalyzeDashboardController: NSWindowController, NSWindowDelegate, AclErrorDelegate {
    
    let appDelegate = NSApplication.shared.delegate as! AppDelegate

    enum ActiveWarningWindow {
        case ingressValidation
        case egressValidation
        case ingressAnalyze
        case egressAnalyze
    }

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
    
    var ingressAccessList: AccessList?
    var egressAccessList: AccessList?
    var activeWarningWindow: ActiveWarningWindow?
    
    override var windowNibName: NSNib.Name? {
        return NSNib.Name("AnalyzeDashboardController")
    }
    
    func windowWillClose(_ notification: Notification) {
    appDelegate.analyzeDashboardControllers.remove(object: self)
    }

    override func windowDidLoad() {
        super.windowDidLoad()

        // Implement this method to handle any initialization after your window controller's window has been loaded from its nib file.
    }
    
    @IBAction func analyzeButton(_ sender: NSButton) {
        self.validateAcl(self)
        ingressAclAnalysis.string = ""
        egressAclAnalysis.string = ""
        let ipProtocol = UInt(protocolButton.selectedTag())
        guard ipProtocol < 256 else {
            self.report(severity: .error, message: "Socket: Invalid IP Protocol", window: .ingressAnalyze)
            return
        }
        guard let sourceIp = sourceIpOutlet.stringValue.ipv4address else {
            self.report(severity: .error, message: "Socket: Invalid source IPv4 address", window: .ingressAnalyze)
            return
        }
        if sourcePortOutlet.stringValue.isEmpty {
            let number = UInt.random(in: 1024 ... 65535)
            sourcePortOutlet.stringValue = "\(number)"
        }
        guard let sourcePort16 = UInt16(sourcePortOutlet.stringValue) else {
            self.report(severity: .error, message: "Socket: Invalid source port", window: .ingressAnalyze)
            return
        }
        let sourcePort = UInt(sourcePort16)
        guard let destinationIp = destinationIpOutlet.stringValue.ipv4address else {
            self.report(severity: .error, message: "Socket: Invalid destination IPv4 address", window: .ingressAnalyze)
            return
        }
        guard let destinationPort16 = UInt16(destinationPortOutlet.stringValue) else {
            self.report(severity: .error, message: "Socket: Invalid destination port", window: .ingressAnalyze)
            return
        }
        let destinationPort = UInt(destinationPort16)

        guard let socket = Socket(ipProtocol: ipProtocol, sourceIp: sourceIp, destinationIp: destinationIp, sourcePort: sourcePort, destinationPort: destinationPort, established: false) else {
            self.report(severity: .error, message: "Unable to specify socket with current configuration", window: .ingressAnalyze)
            return
        }
        self.report(severity: .notification, message: "Socket configured: \(socket)", window: .ingressAnalyze)
        
        activeWarningWindow = .ingressAnalyze
        _ = ingressAccessList?.analyze(socket: socket, delegate: self)
        
        guard let reverseSocket = socket.reverse() else {
            self.report(severity: .error, message: "Unable to generate reverse socket", window: .egressAnalyze)
            return
        }
        self.report(severity: .notification, message: "Socket configured: \(reverseSocket)", window: .egressAnalyze)
        activeWarningWindow = .egressAnalyze
        _ = egressAccessList?.analyze(socket: reverseSocket, delegate: self)

    }
    @IBAction func validateAcl(_ sender: Any) {
        ingressAclValidation.string = ""
        egressAclValidation.string = ""
        let ingressString = ingressAclTextView.string
        let egressString = egressAclTextView.string
        activeWarningWindow = .ingressValidation
        ingressAccessList = AccessList(sourceText: ingressString, delegate: self)
        activeWarningWindow = .egressValidation
        egressAccessList = AccessList(sourceText: egressString, delegate: self)
        activeWarningWindow = nil
        if egressAccessList?.count == 0 {
            egressAccessList = nil
        }
        if ingressAccessList?.count == 0 {
            ingressAccessList = nil
        }
    }
    
    func report(severity: Severity, message: String, line: Int, window: ActiveWarningWindow) {
        self.report(severity: severity, message: "line \(line): \(message)", window: window)
    }
    
    func report(severity: Severity, message: String, line: Int) {
        guard let activeWarningWindow = activeWarningWindow else {
            debugPrint("No active warning window for message \(severity) \(message) \(line)")
            return
        }
        self.report(severity: severity, message: message, line: line, window: activeWarningWindow)
    }
    func report(severity: Severity, message: String, window: ActiveWarningWindow) {
        switch window {
        case .ingressValidation:
            ingressAclValidation.string.append(contentsOf: "\(severity) \(message)\n")
        case .egressValidation:
            egressAclValidation.string.append(contentsOf: "\(severity) \(message)\n")
        case .ingressAnalyze:
            ingressAclAnalysis.string.append(contentsOf: "\(severity) \(message)\n")
        case .egressAnalyze:
            egressAclAnalysis.string.append(contentsOf: "\(severity) \(message)\n")

        }
    }
    func report(severity: Severity, message: String) {
        guard let activeWarningWindow = activeWarningWindow else {
            debugPrint("No active warning window for message \(severity) \(message)")
            return
        }
        self.report(severity: severity, message: message, window: activeWarningWindow)
    }
}
