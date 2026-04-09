import { readdir, readFile } from "fs/promises";
import { basename, relative } from "path";
import { logger } from "../lib/logger";
import type { ParsedPOC } from "../domain/vulnerability";

export class POCParser {
  private parserVersion = "1.0.0";

  async findPOCFiles(inputDir: string): Promise<string[]> {
    const files: string[] = [];

    async function walk(dir: string) {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = `${dir}/${entry.name}`;
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.name.endsWith(".sol") && entry.name.includes("_exp")) {
          files.push(fullPath);
        }
      }
    }

    await walk(inputDir);
    return files;
  }

  async parsePOCFile(filePath: string): Promise<ParsedPOC> {
    const code = await readFile(filePath, "utf-8");
    const { title, attack_title } = this.extractTitle(code, filePath);

    return {
      id: this.generateId(filePath),
      title,
      attack_title: attack_title || title,
      code,
      raw_addresses: [], // No longer extracted - AI handles this
      file_path: relative("./", filePath),
      confidence: 1.0, // AI will determine
    };
  }

  private extractTitle(
    code: string,
    filePath: string,
  ): { title: string; attack_title: string } {
    let title = basename(filePath, ".sol");
    let attack_title = title;

    const commentLines = code
      .split("\n")
      .filter((line) => line.trim().startsWith("//"));

    for (const line of commentLines) {
      const lower = line.toLowerCase();
      if (lower.includes("title") || lower.includes("name")) {
        const match = line.match(/\/\/\s*(?:title|name)[:\s]*([^\n]+)/i);
        if (match) title = match[1].trim();
      }
      if (lower.includes("attack") || lower.includes("vulnerability")) {
        const match = line.match(
          /\/\/\s*(?:attack|vulnerability)[:\s]*([^\n]+)/i,
        );
        if (match) attack_title = match[1].trim();
      }
    }

    if (title === basename(filePath, ".sol")) {
      title = title.replace(/_exp$/, "").replace(/_/g, " ");
    }

    return { title, attack_title };
  }

  private generateId(filePath: string): string {
    return basename(filePath, ".sol")
      .replace(/_exp$/, "")
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "_");
  }

  getVersion(): string {
    return this.parserVersion;
  }
}

export function createPOCParser(): POCParser {
  return new POCParser();
}
