import * as fs from 'fs';
import * as path from 'path';
import { Tool } from '../types';

export class FileSystemTool implements Tool {
  name = 'filesystem';
  description = 'Read and write files in a sandboxed directory';
  private sandboxDir: string;

  constructor(sandboxDir: string = './sandbox') {
    this.sandboxDir = sandboxDir;
    this.ensureSandbox();
  }

  private ensureSandbox(): void {
    if (!fs.existsSync(this.sandboxDir)) {
      fs.mkdirSync(this.sandboxDir, { recursive: true });
    }
  }

  private resolvePath(filePath: string): string {
    const resolved = path.resolve(this.sandboxDir, filePath);
    const normalized = path.normalize(resolved);

    // Security check: ensure path is within sandbox
    if (!normalized.startsWith(path.normalize(this.sandboxDir))) {
      throw new Error(`Access denied: Path ${filePath} is outside sandbox`);
    }

    return normalized;
  }

  async execute(params: Record<string, unknown>): Promise<unknown> {
    const { action, path: filePath, content } = params;

    if (typeof filePath !== 'string') {
      throw new Error('Invalid file path');
    }

    const resolvedPath = this.resolvePath(filePath);

    switch (action) {
      case 'read':
        return this.readFile(resolvedPath);
      case 'write':
        if (typeof content !== 'string') {
          throw new Error('Content must be string');
        }
        return this.writeFile(resolvedPath, content);
      case 'list':
        return this.listDirectory(resolvedPath);
      case 'delete':
        return this.deleteFile(resolvedPath);
      default:
        throw new Error(`Unknown action: ${action}`);
    }
  }

  private readFile(filePath: string): string {
    return fs.readFileSync(filePath, 'utf-8');
  }

  private writeFile(filePath: string, content: string): { success: boolean; path: string } {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, content, 'utf-8');
    return { success: true, path: filePath };
  }

  private listDirectory(dirPath: string): string[] {
    return fs.readdirSync(dirPath);
  }

  private deleteFile(filePath: string): { success: boolean } {
    fs.unlinkSync(filePath);
    return { success: true };
  }
}
