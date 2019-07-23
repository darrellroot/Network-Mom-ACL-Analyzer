//
//  FindDuplicateController.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/23/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

class FindDuplicateController: NSWindowController {

    @IBOutlet weak var deviceTypeOutlet: NSPopUpButton!
    @IBOutlet var aclTextView: NSTextView!
    @IBOutlet var outputTextView: NSTextView!
    
    var fontManager: NSFontManager!

    override var windowNibName: NSNib.Name? {
        return NSNib.Name("FindDuplicateController")
    }

    override func windowDidLoad() {
        super.windowDidLoad()
        self.fontManager = NSFontManager.shared
        if let newFont = fontManager.selectedFont {
            aclTextView.font = newFont
            outputTextView.font = newFont
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
    
    @IBAction func validateButton(_ sender: NSButton) {
    }
    
    @IBAction func analyzeButton(_ sender: NSButton) {
    }
    
}
