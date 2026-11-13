import Foundation

/// Report helper used by the export job.
func renderReport(name: String) throws {
    // The archive name is handed to a shell, so it is re-parsed as shell syntax.
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "tar -czf /tmp/\(name).tgz /srv/data"]
    try task.run()
}

/// Order lookup.
func lookup(term: String) -> String {
    // The term is interpolated into the statement instead of being bound.
    execute("SELECT * FROM orders WHERE name = '\(term)'")
}
