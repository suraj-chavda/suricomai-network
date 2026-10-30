// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
// Design preview: loads the interface in WebKit with sample data and saves a screenshot.
// usage: snapshot <url> <stub.js> <width> <height> <out.png> [pre-load JS] [post-load JS]
import AppKit
import WebKit

let a = CommandLine.arguments
guard a.count >= 6 else { fatalError("usage") }
let url = URL(string: a[1])!
let stub = try String(contentsOfFile: a[2], encoding: .utf8)
let width = Double(a[3])!, height = Double(a[4])!
let out = a[5]
let pre = a.count > 6 ? a[6] : ""
let post = a.count > 7 ? a[7] : ""

final class Logger: NSObject, WKScriptMessageHandler {
    func userContentController(_ c: WKUserContentController, didReceive m: WKScriptMessage) { print("page:", m.body) }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let config = WKWebViewConfiguration()
let logger = Logger()
config.userContentController.add(logger, name: "log")
let hook = """
window.addEventListener('error', e => webkit.messageHandlers.log.postMessage('error: ' + e.message + ' @ ' + e.filename + ':' + e.lineno));
window.addEventListener('unhandledrejection', e => webkit.messageHandlers.log.postMessage('rejection: ' + e.reason));
const _ce = console.error; console.error = (...x) => { webkit.messageHandlers.log.postMessage('console.error: ' + x.join(' ')); _ce(...x); };
try { localStorage.clear(); } catch (e) {}
\(pre)
"""
config.userContentController.addUserScript(WKUserScript(source: hook, injectionTime: .atDocumentStart, forMainFrameOnly: true))
config.userContentController.addUserScript(WKUserScript(source: stub, injectionTime: .atDocumentStart, forMainFrameOnly: true))
let web = WKWebView(frame: NSRect(x: 0, y: 0, width: width, height: height), configuration: config)
let window = NSWindow(contentRect: NSRect(x: -20000, y: -20000, width: width, height: height), styleMask: [.borderless], backing: .buffered, defer: false)
window.contentView = web
window.orderFrontRegardless()

func spin(_ seconds: Double) { RunLoop.main.run(until: Date().addingTimeInterval(seconds)) }
web.load(URLRequest(url: url))
spin(1.6)
if !post.isEmpty {
    web.evaluateJavaScript(post) { _, err in if let err = err { print("post-script error:", err) } }
    spin(1.6)
}
let snap = WKSnapshotConfiguration()
var done = false
web.takeSnapshot(with: snap) { image, error in
    if let image = image, let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
       let png = rep.representation(using: .png, properties: [:]) {
        try? png.write(to: URL(fileURLWithPath: out))
        print("wrote", out, Int(image.size.width), "x", Int(image.size.height))
    } else { print("snapshot failed", error as Any) }
    done = true
}
while !done { spin(0.1) }
