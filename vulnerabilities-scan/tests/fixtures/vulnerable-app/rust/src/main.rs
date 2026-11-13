// Order lookup helper used by the batch importer.
use std::fs;
use std::process::Command;

fn execute(statement: &str) -> String {
    // The fixture has no database driver: the sink is the call that receives
    // the assembled statement, which is what the rule matches.
    statement.to_string()
}

pub fn list_orders(term: String) -> String {
    // The term is interpolated into the statement, so it becomes SQL syntax.
    execute(&format!("SELECT * FROM orders WHERE name = '{}'", term))
}

pub fn render_report(name: String) {
    // The archive name comes from the caller and is handed to a shell.
    Command::new("sh")
        .arg("-c")
        .arg(format!("tar -czf /tmp/{}.tgz /srv/data", name))
        .status()
        .expect("tar failed");
}

pub fn read_document(name: String) -> String {
    // The path is interpolated and opened directly, so ../ escapes /srv/data.
    fs::read_to_string(format!("/srv/data/{}", name)).unwrap_or_default()
}
