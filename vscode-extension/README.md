# DevSecOps Policy Scanner — VS Code Extension

A VS Code extension that scans Terraform, Dockerfile, and Kubernetes YAML files for security violations in real-time using the DevSecOps Policy Service.

## Features

- **Scan on Save**: Automatically scans files when you save them
- **Inline Diagnostics**: Shows violations as errors/warnings directly in the editor
- **Auto-Fix**: One-click fix for common security violations
- **Configurable**: Set service URL, threshold, and auto-scan behavior

## Requirements

- The DevSecOps Policy Service must be running (default: `http://localhost:8000`)
- Start it with: `python main.py` or `docker-compose up`

## Installation (Development Mode)

Since this extension is not published to the marketplace, install it in development mode:

1. Copy the `vscode-extension` folder to `~/.vscode/extensions/devsecops-policy-scanner`
2. Restart VS Code
3. The extension activates automatically for `.tf`, `Dockerfile`, and `.yaml` files

**Or** press `F5` in VS Code while this folder is open to run in Extension Development Host.

## Usage

### Automatic Scanning
Open any `.tf`, `Dockerfile`, or `.yaml` file and save it. Violations appear as:
- 🔴 **Errors** — CRITICAL and HIGH severity
- 🟡 **Warnings** — MEDIUM severity  
- 🔵 **Info** — LOW severity
- 💡 **Hints** — INFO severity

### Manual Commands
- `Ctrl+Shift+P` → **DevSecOps: Scan Current File**
- `Ctrl+Shift+P` → **DevSecOps: Auto-Fix Current File**

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `devsecops.serviceUrl` | `http://localhost:8000` | Policy service URL |
| `devsecops.scanOnSave` | `true` | Auto-scan on file save |
| `devsecops.blockThreshold` | `LOW` | Minimum severity for errors |

## Demo

1. Start the policy service: `python main.py`
2. Open a Terraform file with insecure code
3. Save the file → violations appear inline
4. Run **DevSecOps: Auto-Fix Current File** → code is corrected
5. Save again → violations disappear ✅
