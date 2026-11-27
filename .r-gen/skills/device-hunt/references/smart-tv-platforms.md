# Smart TV platform review

Load this reference only after device evidence supports a platform. Platform labels are hypotheses until corroborated by service metadata, authenticated host evidence, firmware metadata, or an operator declaration.

## Android TV and Android-based media devices

- Correlate build fingerprint, security patch level, kernel, SELinux state, verified boot state, package inventory, update channel, and exposed Android services.
- Treat ADB as a privileged management surface. Do not enable it, pair a client, approve a debug key, install an APK, grant permissions, or alter developer settings.
- If ADB is already exposed, report reachability and authentication posture through a registered executor; never assume a banner proves practical access.
- Review exported components, intent filters, content providers, deep links, WebViews, JavaScript bridges, network-security configuration, backup/debug flags, signing identity, and permission use from acquired app artifacts.
- Separate platform packages, vendor packages, operator packages, and user-installed applications when the evidence permits it.

## Samsung Tizen

- Correlate model and firmware identifiers, Tizen version, application manifests, privileges, certificates, update metadata, and exposed remote-management services.
- Treat developer mode, device-manager pairing, certificate installation, package deployment, debugging, and shell access as persistent privileged changes. Do not activate them.
- Review web applications for CSP, mixed content, remote resources, JavaScript bridges, privilege declarations, origin controls, certificate chains, and update trust.
- Do not infer exploitability from a Tizen or component version alone; require reachability and behavioral evidence.

## LG webOS

- Correlate model and firmware identifiers, webOS version, service manifests, Luna-service exposure, application metadata, update state, and developer-mode state.
- Do not enable developer mode, pair developer tooling, obtain a shell, install packages, or invoke state-changing Luna methods.
- Review web applications for CSP, remote content, bridges, permissions, origin controls, certificate use, local storage, and update behavior.
- Treat undocumented service methods and developer endpoints as privileged until a deterministic contract classifies them.

## Cross-platform interpretation

- Map observations to the exact hardware model, region, firmware build, application version, and enabled feature set.
- Distinguish stock behavior from operator configuration and installed third-party applications.
- Prefer signed manifests, package metadata, and direct runtime evidence over product-family assumptions.
- Record unsupported or unknown platform facts as coverage gaps. Never substitute commands or vendor tooling that is not a registered ShakerScan executor.
