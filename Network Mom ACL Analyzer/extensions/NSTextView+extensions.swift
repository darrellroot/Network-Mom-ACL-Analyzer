//
//  NSTextView+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/25/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Cocoa

extension NSTextView {
    public var substituteFontName : String {
        get {
            return self.font?.fontName ?? "";
        }
        set {
            let fontNameToTest = self.font?.fontName.lowercased() ?? "";
            var fontName = newValue;
            if fontNameToTest.range(of: "bold") != nil {
                fontName += "-Bold";
            } else if fontNameToTest.range(of: "medium") != nil {
                fontName += "-Medium";
            } else if fontNameToTest.range(of: "light") != nil {
                fontName += "-Light";
            } else if fontNameToTest.range(of: "ultralight") != nil {
                fontName += "-UltraLight";
            }
            self.font = NSFont(name: fontName, size: self.font?.pointSize ?? 17)
        }
    }
}
