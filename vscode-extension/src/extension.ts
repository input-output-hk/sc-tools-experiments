// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "sc-testing-tools" is now active!');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	const disposable = vscode.commands.registerCommand('sc-testing-tools.helloWorld', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World from sc-testing-tools!123');
	});

	context.subscriptions.push(disposable);

	const controller = vscode.tests.createTestController(
		'sc-testing-tools-test',
		'Plinth test'
	);
	context.subscriptions.push(controller);

	function updateNodeForDocument(e: vscode.TextDocument) {
		if (e.uri.scheme !== 'file') {
			return;
		}

		if (!e.uri.path.endsWith('.hs')) {
			return;
		}

		controller.items.add(controller.createTestItem(e.uri.path, "Test " + e.uri.path.split("/").pop(), e.uri));
	}

	for (const document of vscode.workspace.textDocuments) {
		updateNodeForDocument(document);
	}

	context.subscriptions.push(
		vscode.workspace.onDidOpenTextDocument(updateNodeForDocument)
	);

	function runHandler(
		shouldDebug: boolean,
		request: vscode.TestRunRequest,
		token: vscode.CancellationToken
	) {
		const run = controller.createTestRun(request);
		if (request.include?.[0]?.uri) {
			run.addCoverage(new vscode.FileCoverage(
				request.include[0].uri,
				new vscode.TestCoverageCount(20, 20),
				undefined,
				undefined,
				[request.include[0]]
			));
		}
		run.end();
	}

	const coverageProfile = controller.createRunProfile(
		'Coverage',
		vscode.TestRunProfileKind.Coverage,
		(request, token) => {
			runHandler(false, request, token);
		}
	);

	coverageProfile.loadDetailedCoverage = async (_testRun, coverage) => {
		let relPath = vscode.workspace.asRelativePath(coverage.uri);
		let coverageFile = (await vscode.workspace.findFiles('**/coverage-report.ignore.txt', null, 1)).at(0);
		if (!coverageFile) {
			vscode.window.showErrorMessage("No coverage file found");
			return [];
		}
		let coverageBaseParts = vscode.workspace.asRelativePath(coverageFile).split("/");
		coverageBaseParts.pop();
		let coverageBase = coverageBaseParts.join("/") + "/";
		if (!relPath.startsWith(coverageBase)) {
			vscode.window.showErrorMessage(`Found coverage file at ${vscode.workspace.asRelativePath(coverageFile)}, which doesn't include coverage for ${relPath}.`);
			return [];
		};
		relPath = relPath.replace(coverageBase, "");
		let rawContent = await vscode.workspace.fs.readFile(coverageFile);
		let [_,covered,uncovered,ignored] = (await vscode.workspace.decode(rawContent)).split(/=+\[\w+\]=+/);
		return [
			...parseRanges(relPath, covered).map(rng => new vscode.StatementCoverage(true, rng)),
			...parseRanges(relPath, uncovered).map(rng => new vscode.StatementCoverage(false, rng)),
		];
	};

	function parseRanges(relPath: string, coverageData: string) {
		let lines = coverageData.split("\n");
		return lines.flatMap(line => {
			if (line) {
				let [fname,rng] = line.split(":");
				if (relPath === fname) {
					let [p1, p2] = rng.split("-");
					return new vscode.Range(parsePos(p1), parsePos(p2));
				} else {
					return [];
				}
			} else {
				return [];
			}
		});
	}

	function parsePos(pos: string) {
		let [l,c] = pos.split(",");
		return new vscode.Position(+l - 1, +c - 1);
	}
}

// This method is called when your extension is deactivated
export function deactivate() {}
