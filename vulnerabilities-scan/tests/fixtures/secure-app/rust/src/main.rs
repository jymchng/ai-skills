// Order lookup helper, secure mirror image of the vulnerable one.
use std::fs;
use std::process::Command;

fn execute_bound(statement: &str, term: &str) -> String {
    // The statement is constant; the value travels as a bound parameter.
    format!("{} [{}]", statement, term)
}

pub fn list_orders(term: String) -> String {
    execute_bound("SELECT * FROM orders WHERE name = $1", &term)
}

pub fn render_report(name: String) {
    // Argument vector, no shell.
    Command::new("tar")
        .arg("-czf")
        .arg("/tmp/report.tgz")
        .arg(&name)
        .status()
        .expect("tar failed");
}

pub fn read_document(name: String) -> String {
    // Reduced to a file name inside the data root, then joined as a path.
    let safe = name.rsplit('/').next().unwrap_or("");
    let path = std::path::Path::new("/srv/data").join(safe);
    fs::read_to_string(path).unwrap_or_default()
}
