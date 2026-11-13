import Foundation

/// Report helper, secure mirror image of the vulnerable one.
func renderReport(name: String) throws {
    // Argument vector, no shell, and only the file name component is used.
    let safe = (name as NSString).lastPathComponent
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
    task.arguments = ["-czf", "/tmp/report.tgz", "/srv/data/\(safe)"]
    try task.run()
}

/// Order lookup.
func lookup(term: String) -> String {
    // The statement is constant and the value travels as a bound parameter.
    execute("SELECT * FROM orders WHERE name = $1", [term])
}
