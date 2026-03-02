# Contributing to FDSec 🛡️

First of all, thank you for considering contributing to **FDSec**! As a security project, your help is vital to making this antivirus more robust and effective for everyone.

Since the project is currently in its early stages (centered around `Program.cs`), we are looking for contributors to help modularize the engine and expand its detection capabilities.

---

## 📋 Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Development Environment](#development-environment)
3. [How to Contribute](#how-to-contribute)
4. [Coding Standards](#coding-standards)
5. [Pull Request Process](#pull-request-process)
6. [Security Vulnerabilities](#security-vulnerabilities)
7. [License](#license)

---

## 🤝 Code of Conduct
By participating in this project, you agree to maintain a professional and respectful environment. Please be constructive and helpful to fellow contributors.

## 💻 Development Environment
To build and test FDSec, you will need:
* **Visual Studio 2019/2022** (with .NET Desktop Development workload).
* **.NET Framework 4.7.2 SDK** or higher.
* **Administrator Privileges** (often required for testing file system hooks or deep scans).

---

## 🚀 How to Contribute

### Reporting Bugs
If you find a bug, please open an **Issue** with:
* A clear description of the error.
* Steps to reproduce the behavior.
* Your Windows version and .NET Runtime version.

### Suggesting Features
We are currently focusing on:
* **Refactoring:** Breaking down `Program.cs` into modular classes (e.g., `Scanner`, `Heuristics`, `Database`).
* **Scanning Engine:** Implementing efficient hash-based (MD5/SHA256) or string-based detection.
* **GUI Development:** Moving from a console app to a graphical interface (WPF/WinForms).

---

## 🛠 Coding Standards (C#)
To keep the codebase clean and secure:
* **Naming:** Use `PascalCase` for methods/classes and `camelCase` for local variables.
* **Language Version:** Stick to **C# 7.3** features unless the project file is explicitly updated for newer versions.
* **Resource Management:** Always use `using` statements for `FileStream` or any `IDisposable` objects to prevent memory leaks and handle file locks properly.
* **P/Invoke:** Any use of `[DllImport]` for Windows APIs must be clearly documented and tested for stability.

---

## 📬 Pull Request Process
1. **Fork** the repository and create your branch from `main`.
2. Ensure your code compiles without warnings.
3. If you introduce new files (splitting `Program.cs`), include the updated `.csproj` file.
4. Open a **Pull Request** describing your changes and link any related issues (e.g., `Fixes #1`).

---

## 🛡️ Security Vulnerabilities
**IMPORTANT:** If you discover a security vulnerability within FDSec itself (e.g., a way for malware to bypass or disable the engine), **do not open a public Issue**. Please contact the maintainers privately so we can release a patch before the vulnerability is made public.

---

## ⚖️ License
By contributing to FDSec, you agree that your contributions will be licensed under the **GNU GPL v3 License**. You must ensure that any code or libraries you add are compatible with this license.

