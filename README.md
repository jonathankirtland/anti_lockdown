# Lockdown Browser Bypass

## Overview

**Lockdown Browser Bypass** is a proof-of-concept application that demonstrates methods for circumventing certain proprietary Lockdown Browser restrictions.

Please note that the included instructions and binaries are for demonstration and research only. No part of this repository is intended to encourage malicious activity.

---

## Features

- **Bypass Launch**: Attempts to launch restricted applications or processes that are typically blocked by the Lockdown Browser.
- **Modular Design**: Easily integrate new bypass techniques as plugins or modules.
- **Logging & Analysis**: Basic activity logs to help researchers understand where and why a bypass was successful.

---

## Requirements

**To Run (Pre-built Binary)**:
- **Operating System**: Windows 10 or newer.
- **Architecture**: The provided executable is compiled for **x86**.
- **Permissions**: The launcher must be **run as Administrator** for the bypass to function properly.
- **Dependencies**: None required to simply run the pre-built executable. You do *not* need the Windows Developer Kit or C++ runtime if you are only running the provided binary.
- You do need this [Visual C++ Runtime x86](https://aka.ms/vs/16/release/vc_redist.x86.exe)

**To Build From Source**:
- **Windows Developer Kit** (required to access the required headers and libraries).
- **Microsoft Visual C++ Runtime** and **Windows SDK**:  
  It’s highly recommended to install the latest [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170) and the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) for a stable build environment.  
  *Note:* Having the SDK is recommended if Lockdown Browser vendors start implementing signature detections, as you may need to modify code and recompile quickly. You can install it through Visual Studio Code
- **Compiler**: Visual Studio or MSBuild with the above dependencies installed.
- **Build Architecture**: **x86** mode is required for this project.

---

## Installation & Running

1. **Pre-Built Executable**:
   - Download `launcher.exe` and `DLL.dll` from `release.zip`, located in the [Releases](./releases) section.
   - Right-click the executable and select **"Run as administrator"**.
   - Follow on-screen prompts.

2. **Building from Source**:
   - Ensure you have Visual Studio (with C++ workload), the Windows SDK, and the Microsoft Visual C++ Redistributable installed.
   - Open a Developer Command Prompt for VS or a VS terminal.
   - Navigate to the project directory:
     ```powershell
     cd path\to\anti_lockdown
     ```
   - Run MSBuild (or open the `.sln` in Visual Studio and build):
     ```powershell
     msbuild LDB_Bypass.sln /p:Configuration=Release /p:Platform=x86
     ```
   - Once built successfully, navigate to the `Release` folder and run the executable as administrator.

---

## Usage

1. **Launching**:
   - Ensure all Lockdown Browser processes are closed.
   - Launch `launcher.exe` **as administrator**.
   - The app will attempt to start processes that would typically be blocked by the Lockdown Browser.

---

## Contributing

Research contributions, bug reports, and PRs are welcome, but please:

- Respect the project’s ethical guidelines.
- Use a clear description of what changes you are making and why.
- Document any new bypass techniques thoroughly.

---

## License

This project is licensed under the [MIT License](./LICENSE).

---
