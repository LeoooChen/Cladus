fn main() {
    #[cfg(windows)]
    {
        // The web assets are embedded at compile time. Without a frontend
        // build (e.g. `cargo test` on a machine without Node), embed a page
        // that says so instead of failing the whole workspace.
        let dist = std::path::Path::new("../dist");
        if !dist.join("index.html").exists() {
            std::fs::create_dir_all(dist).expect("cannot create ../dist");
            std::fs::write(
                dist.join("index.html"),
                "<!doctype html><title>Cladus</title><p>The Cladus frontend was not built. \
                 Run <code>npm run build</code> in apps/cladus-gui and rebuild.</p>",
            )
            .expect("cannot write the placeholder page");
        }
        tauri_build::build();
    }
}
