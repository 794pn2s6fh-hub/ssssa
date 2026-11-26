# FairPlayed OnDevice — FairPlay + optional pairing/Airlift diagnostics

This project keeps FairPlayed's native on-device FairPlay path as the **primary** IPA-processing mechanism. The Erosion pairing and Airlift code is an optional fallback/diagnostic layer; it is not run automatically when an IPA is imported.

## What is included

- **Primary FairPlayed path** — the existing Objective-C/C IPA importer, Mach-O parser, `mremap_encrypted` experiments, and IPA exporter remain in place. The imported-IPA path is still experimental: upstream's confirmed workflow embeds the target app in `FairPlayed.app` before installation, because `fairplayd` cannot read an arbitrary copy in an app Data Container. This build keeps the on-device import test and adds an installed-bundle route to investigate that boundary; it does not claim that arbitrary imported IPAs now decrypt successfully.
- **RPPairing** — create an RPPairing file from the iPhone itself, or import an existing RPPairing plist. Imported files are validated and stored in protected `Library/Application Support/FairPlayedLab/` storage; generic legacy lockdown `.mobiledevicepairing` records are not accepted.
- **InstallationProxy** — use the pairing file and an active LocalDevVPN loopback tunnel to call `com.apple.mobile.installation_proxy`. The scan returns app metadata and installed `.app` bundle paths. This is metadata discovery, not filesystem access by itself.
- **Native probe through InstallationProxy** — after a scan, FairPlayed can try its existing native `fp_probe_file` mechanism directly against the exact installed `.app` path returned by InstallationProxy.
- **Airlift AFC-only folder read** — as the first, optional read fallback, export one selected installed `.app` bundle through AFC list/get/open/read calls only. This path does not invoke AirTraffic or write to the device.
- **Airlift restore-transaction folder read** — a separate, more invasive diagnostic action that invokes the existing AirTraffic staging/restore reader only after the user explicitly confirms it.

## Pairing and LocalDevVPN

A pairing file alone is not enough for the Airlift/InstallationProxy calls in this build. The Erosion Airlift Rust implementation connects to RSD/Lockdown at `127.0.0.1` and the `10.7.0.x` addresses. Therefore, the existing **LocalDevVPN loopback tunnel must already be active**. The app checks for an active `utun`/`ipsec` interface with a `10.7.x` address and reports a clear error if it is missing. The app list is scrollable independently from the diagnostic log. This project does not create or enable the VPN profile.

To create a pairing file:

1. Install FairPlayed Lab on the iPhone.
2. Tap **Pair this iPhone**.
3. Approve the local-network prompt.
4. Open **Settings → Privacy & Security → Developer Mode → Pair with FairPlayed** and enter the PIN shown in the app.
5. Return to FairPlayed; the RPPairing file is saved in protected Application Support storage, outside Documents and the Share export list.

Or use **Import pairing file** to import an existing RPPairing plist. Generic legacy lockdown `.mobiledevicepairing` records are not accepted by the current validator. The pairing file contains a private key. It is stored with iOS file protection outside Documents; keep imported source copies private too.

## Suggested test order

1. Try **Import encrypted IPA (primary)** first. This invokes the original FairPlayed path and does not require Airlift.
2. If you want to test an app already installed from the App Store, create/import a pairing file and enable the existing LocalDevVPN tunnel.
3. Tap **Scan apps via InstallationProxy**. The complete response is saved to `Documents/AirliftDiagnostics/installationproxy.json`; the on-screen result also lists a sample of discovered bundle IDs for the next test.
4. Tap **Native FairPlayed probe via InstallationProxy** and enter the exact Bundle ID from the scan. This attempts the original FairPlayed `mremap_encrypted` probe using the actual installed bundle path.
5. Only if needed, try **Airlift AFC-only read .app (safe first)**. It performs AFC reads only; if AFC refuses the protected path, it stops and does not escalate automatically.
6. The separate **Airlift full read .app (restore transaction)** action is optional and requires explicit confirmation. It invokes AirTraffic staging/restore. The app checks `restoreConfirmed` and `restoreHandoffCompleted`; if either is false it emits an explicit safety warning and tells you not to launch the target app until its original bundle is verified. Both outputs are saved under `Documents/AirliftExports/` and can be shared with the Share button.

## Important technical limits

- InstallationProxy returns metadata (including `Path`/`ApplicationPath`) and does not itself grant permission to read the bundle.
- The native probe against an installed bundle may still fail if the app process cannot open the executable or if `mremap_encrypted` rejects the request (for example, `EINVAL`). A pairing file does not change the arguments/semantics of that syscall.
- The first Airlift path, `al_exploit_read_afc_only_folder`, uses AFC list/get/open/read only and never invokes AirTraffic or writes to the device. AFC may deny protected Bundle/Application paths. The separate `al_exploit_read_folder` path is not a plain `FileManager` copy: it performs a temporary remote staging/restore transaction. It is never selected automatically. If you explicitly run it, keep the target app closed until restoration is confirmed; if it reports a safety warning, do not launch the target app until its original bundle is verified.
- An Airlift-exported `.app` ZIP is an inspection copy in this app's Data Container. It is **not** automatically a valid FairPlay input: upstream FairPlayed documents that `fairplayd` can access installed bundles but not arbitrary app Data Container paths. The ZIP is exported for inspection, not silently fed into the primary decrypt path.
- No JIT is used by the FairPlayed native C path or by the pairing/Airlift FFI wrapper. The optional Airlift folder reader uses its existing AirTraffic-based read implementation; it is not equivalent to a jailbreak-free public filesystem API.
- This is research software. The supplied Erosion/Airlift project targets iOS 27+ at runtime; the Xcode deployment target is left at 18.0 for build compatibility, not as a claim that these services work on iOS 18. A successful build does not prove that pairing, LocalDevVPN, InstallationProxy, or the iOS kernel syscall will succeed on every iOS version.

## Build without a local Mac

The GitHub Actions workflow builds the Airlift Rust static library for `aarch64-apple-ios`, links it into FairPlayed, builds an unsigned `.app`, and packages an unsigned IPA.

1. Push this project to a GitHub repository.
2. Open **Actions**.
3. Run **Build FairPlayed On-Device (unsigned IPA)**.
4. Download the `FairPlayed-OnDevice-unsigned-IPA` artifact.
5. Sign and install it with your normal sideloading tool.

The workflow uses a macOS GitHub runner; a local Mac is not required. It installs `llvm-tools-preview` and uses the Rust toolchain's matching `llvm-nm` to inspect the Rust static library. Do not replace this with Xcode's `/usr/bin/nm`: Xcode 16.4's Apple `nm` may fail on newer LLVM object attributes emitted by recent Rust toolchains (`Unknown attribute kind`). The Rust dependency graph includes a pinned `idevice` revision and the vendored Airlift Rust sources under `FairPlayed/Airlift/rust-core/`.

## Third-party source

The Airlift Rust core and pairing/Airlift Swift support were adapted from the Erosion/AirCard source supplied for this task. The Rust core is included as source and built in CI; no Git LFS placeholder static library is used. The included AirCard/Airlift MIT license is in `THIRD-PARTY-LICENSE-AIRLIFT-MIT.txt`.
