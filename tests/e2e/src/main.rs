#[cfg(windows)]
mod windows;

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    {
        windows::main()
    }
    #[cfg(not(windows))]
    {
        eprintln!("The WinDivert acceptance test requires Windows.");
        std::process::ExitCode::FAILURE
    }
}
