//! Build script — winres for Windows icon/manifest/version.
//! Uses CARGO_CFG_TARGET_OS to work correctly during cross-compilation.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let icon_path = std::path::Path::new(&manifest_dir).join("icon.ico");

        let mut res = winres::WindowsResource::new();
        // Cross-compilation: explicit paths to mingw toolchain
        res.set_toolkit_path("/usr/bin");
        res.set_ar_path("/usr/bin/x86_64-w64-mingw32-ar");
        res.set_windres_path("/usr/bin/x86_64-w64-mingw32-windres");
        res.set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="rsh" version="5.0.0.0" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
    </application>
  </compatibility>
</assembly>"#,
        );
        res.set_icon(icon_path.to_str().unwrap());
        res.set("ProductName", "Remote Shell (rsh)");
        res.set("FileDescription", "Remote Shell Tool");
        res.set("CompanyName", "MDP");
        let year = option_env!("BUILD_YEAR").unwrap_or("2026");
        res.set("LegalCopyright", &format!("Copyright {year} MDP"));
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=winres failed: {e}");
        }

        // GNU ld doesn't pull .rsrc from static archives (no symbol references).
        // Link the resource object directly so the .rsrc section is included.
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let res_obj = std::path::Path::new(&out_dir).join("resource.o");
        if res_obj.exists() {
            println!("cargo:rustc-link-arg={}", res_obj.display());
        }
    }
}
