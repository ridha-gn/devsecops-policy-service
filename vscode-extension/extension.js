// ============================================================
// DevSecOps Policy Scanner — VS Code Extension
// Scans infrastructure files on save and shows violations inline
// ============================================================

const vscode = require('vscode');
const http = require('http');
const https = require('https');

/** @type {vscode.DiagnosticCollection} */
let diagnosticCollection;

// Map file extensions to code types
const CODE_TYPE_MAP = {
    '.tf': 'terraform',
    '.hcl': 'terraform',
    'Dockerfile': 'dockerfile',
    '.yaml': 'yaml',
    '.yml': 'yaml',
};

// Map severity to VS Code diagnostic severity
const SEVERITY_MAP = {
    'CRITICAL': vscode.DiagnosticSeverity.Error,
    'HIGH': vscode.DiagnosticSeverity.Error,
    'MEDIUM': vscode.DiagnosticSeverity.Warning,
    'LOW': vscode.DiagnosticSeverity.Information,
    'INFO': vscode.DiagnosticSeverity.Hint,
};


/**
 * Detect the code type from a file URI.
 * @param {vscode.Uri} uri
 * @returns {string|null}
 */
function detectCodeType(uri) {
    const path = uri.fsPath;
    const basename = path.split(/[\\/]/).pop() || '';

    if (basename === 'Dockerfile' || basename.startsWith('Dockerfile.')) {
        return 'dockerfile';
    }

    for (const [ext, type] of Object.entries(CODE_TYPE_MAP)) {
        if (path.endsWith(ext)) return type;
    }

    return null;
}


/**
 * Send HTTP POST request to the policy service.
 * @param {string} url
 * @param {object} data
 * @returns {Promise<object>}
 */
function postRequest(url, data) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;
        const payload = JSON.stringify(data);

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
            },
            timeout: 10000,
        };

        const req = client.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    reject(new Error(`Invalid JSON response: ${body.substring(0, 200)}`));
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.write(payload);
        req.end();
    });
}


/**
 * Scan a document and update diagnostics.
 * @param {vscode.TextDocument} document
 */
async function scanDocument(document) {
    const codeType = detectCodeType(document.uri);
    if (!codeType) return;

    const config = vscode.workspace.getConfiguration('devsecops');
    const serviceUrl = config.get('serviceUrl', 'http://localhost:8000');
    const threshold = config.get('blockThreshold', 'LOW');

    try {
        const result = await postRequest(`${serviceUrl}/analyze`, {
            code_type: codeType,
            content: document.getText(),
            filename: document.fileName.split(/[\\/]/).pop(),
            block_threshold: threshold,
        });

        const diagnostics = [];

        for (const violation of (result.violations || [])) {
            const line = Math.max(0, (violation.line || 1) - 1);
            const range = new vscode.Range(
                new vscode.Position(line, 0),
                new vscode.Position(line, Number.MAX_SAFE_INTEGER)
            );

            const severity = SEVERITY_MAP[violation.severity] || vscode.DiagnosticSeverity.Warning;

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${violation.rule}] ${violation.message}`,
                severity
            );
            diagnostic.source = 'DevSecOps';
            diagnostic.code = violation.rule;

            // Add fix recommendation as related info
            if (violation.recommendation) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `Fix: ${violation.recommendation}`
                    )
                ];
            }

            diagnostics.push(diagnostic);
        }

        diagnosticCollection.set(document.uri, diagnostics);

        // Show summary in status bar
        const decision = result.decision || 'UNKNOWN';
        const count = (result.violations || []).length;
        if (decision === 'BLOCK') {
            vscode.window.showWarningMessage(
                `🚫 DevSecOps: ${count} violation(s) found — BLOCK`
            );
        } else if (count > 0) {
            vscode.window.showInformationMessage(
                `⚠️ DevSecOps: ${count} violation(s) found — ALLOW (below threshold)`
            );
        } else {
            vscode.window.showInformationMessage(
                '✅ DevSecOps: No violations — code is compliant'
            );
        }

    } catch (error) {
        vscode.window.showErrorMessage(
            `DevSecOps: Service unavailable at ${serviceUrl} — ${error.message}`
        );
    }
}


/**
 * Auto-fix the current file.
 * @param {vscode.TextDocument} document
 */
async function fixDocument(document) {
    const codeType = detectCodeType(document.uri);
    if (!codeType) {
        vscode.window.showWarningMessage('DevSecOps: Unsupported file type');
        return;
    }

    const config = vscode.workspace.getConfiguration('devsecops');
    const serviceUrl = config.get('serviceUrl', 'http://localhost:8000');

    try {
        const result = await postRequest(`${serviceUrl}/fix`, {
            code_type: codeType,
            content: document.getText(),
        });

        if (result.total_fixes === 0) {
            vscode.window.showInformationMessage(
                '✅ DevSecOps: No fixes needed — code is already secure'
            );
            return;
        }

        // Apply the fixed code
        const edit = new vscode.WorkspaceEdit();
        const fullRange = new vscode.Range(
            document.positionAt(0),
            document.positionAt(document.getText().length)
        );
        edit.replace(document.uri, fullRange, result.fixed_code);
        await vscode.workspace.applyEdit(edit);

        vscode.window.showInformationMessage(
            `🔧 DevSecOps: Applied ${result.total_fixes} fix(es)`
        );

        // Re-scan after fix
        await scanDocument(document);

    } catch (error) {
        vscode.window.showErrorMessage(
            `DevSecOps: Auto-fix failed — ${error.message}`
        );
    }
}


/**
 * Extension activation.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('DevSecOps Policy Scanner activated');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('devsecops');
    context.subscriptions.push(diagnosticCollection);

    // Command: Scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('devsecops.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) scanDocument(editor.document);
        })
    );

    // Command: Auto-fix current file
    context.subscriptions.push(
        vscode.commands.registerCommand('devsecops.fixFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) fixDocument(editor.document);
        })
    );

    // Auto-scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('devsecops');
            if (config.get('scanOnSave', true)) {
                scanDocument(document);
            }
        })
    );

    // Scan currently open file on activation
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}


function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

module.exports = { activate, deactivate };
