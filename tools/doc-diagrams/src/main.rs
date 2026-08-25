use std::process::ExitCode;

fn main() -> ExitCode {
    let check = std::env::args().skip(1).any(|arg| arg == "--check");
    let root = doc_diagrams::workspace_root();
    match doc_diagrams::write_all(&root, check) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("doc-diagrams: {error}");
            ExitCode::FAILURE
        }
    }
}
