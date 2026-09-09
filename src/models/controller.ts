import * as vscode from 'vscode';
import { HttpMethod } from './route';

export interface ControllerEndpoint {
	controllerClass: string;
	methodName: string;
	httpMethod: HttpMethod;
	path: string;
	fullPath: string;
	methodSecurity?: string;
	file: vscode.Uri;
	line: number;
	column: number;
}
