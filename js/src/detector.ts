/**
 * ShieldPipe - Core PII Detection Engine
 * Multi-layer entity detection with consistent pseudonymization
 */

import { readFileSync, writeFileSync, existsSync, appendFileSync } from "fs";
import { resolve, dirname } from "path";
import { createHash, randomBytes, createCipheriv, createDecipheriv } from "crypto";

export type EntityType =
  | "EMAIL"
  | "PHONE"
  | "IP_ADDRESS"
  | "URL_INTERNAL"
  | "API_KEY"
  | "JWT"
  | "CREDIT_CARD"
  | "SSN"
  | "PERSON"
  | "ORG"
  | "AMOUNT"
  | "DATE"
  | "ADDRESS"
  | "CUSTOM";

export interface DetectedEntity {
  type: EntityType;
  value: string;
  token: string;
  start: number;
  end: number;
}

export interface DetectionConfig {
  emails?: boolean;
  phones?: boolean;
  ipAddresses?: boolean;
  internalUrls?: boolean;
  apiKeys?: boolean;
  jwts?: boolean;
  creditCards?: boolean;
  ssns?: boolean;
  amounts?: boolean;
  dates?: boolean;
  customPatterns?: CustomPattern[];
  preserve?: string[]; // never pseudonymize these
  force?: string[];    // always pseudonymize these
}

export interface CustomPattern {
  name: string;
  regex: string | RegExp;
  category: string;
}

const DEFAULT_CONFIG: DetectionConfig = {
  emails: true,
  phones: true,
  ipAddresses: true,
  internalUrls: true,
  apiKeys: true,
  jwts: true,
  creditCards: true,
  ssns: false,
  amounts: true,
  dates: false,
};

// Regex patterns for each entity type
const PATTERNS: Record<string, RegExp> = {
  EMAIL: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  PHONE: /(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
  IP_ADDRESS: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  URL_INTERNAL: /https?:\/\/(?:localhost|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|(?:[a-z0-9\-]+\.)?(?:internal|local|intranet|corp|private))[^\s]*/gi,
  API_KEY: /\b(?:sk-[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{32,}(?:key|token|secret|api)[a-zA-Z0-9]*|(?:key|token|secret|api)[a-zA-Z0-9]*[=:]\s*[a-zA-Z0-9_\-]{16,})\b/gi,
  JWT: /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g,
  CREDIT_CARD: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  SSN: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  AMOUNT: /(?:(?:USD|EUR|GBP|INR|Rs\.?|₹|\$|€|£)\s*\d+(?:[.,]\d{3})*(?:\.\d{2,3})?\s*(?:USD|EUR|GBP|INR|million|billion|M|B|K|L|Cr|lakh|crore)?|\b\d+(?:[.,]\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|INR|million|billion|lakh|crore)\b|\b\d+(?:\.\d+)?\s*[MBK]\b)/gi,
  DATE: /\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{2}[\/\-\.]\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}|Q[1-4]\s+\d{4})\b/gi,
};

const CONFIG_KEY_MAP: Record<string, keyof DetectionConfig> = {
  EMAIL: "emails",
  PHONE: "phones",
  IP_ADDRESS: "ipAddresses",
  URL_INTERNAL: "internalUrls",
  API_KEY: "apiKeys",
  JWT: "jwts",
  CREDIT_CARD: "creditCards",
  SSN: "ssns",
  AMOUNT: "amounts",
  DATE: "dates",
};

export class PIIDetector {
  private config: DetectionConfig;
  private counters: Map<string, number> = new Map();
  private vault: Map<string, string> = new Map(); // value -> token
  private reverseVault: Map<string, string> = new Map(); // token -> value

  constructor(config: Partial<DetectionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  detect(text: string): DetectedEntity[] {
    const entities: DetectedEntity[] = [];
    const seen = new Set<string>();
    const preserveSet = new Set(this.config.preserve ?? []);

    for (const [typeKey, pattern] of Object.entries(PATTERNS)) {
      const configKey = CONFIG_KEY_MAP[typeKey];
      if (configKey && this.config[configKey] === false) continue;

      const regex = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
      let match;
      while ((match = regex.exec(text)) !== null) {
        const value = match[0];
        if (preserveSet.has(value)) continue;
        if (seen.has(`${match.index}-${value}`)) continue;
        seen.add(`${match.index}-${value}`);

        const token = this.getOrCreateToken(typeKey as EntityType, value);
        entities.push({
          type: typeKey as EntityType,
          value,
          token,
          start: match.index,
          end: match.index + value.length,
        });
      }
    }

    for (const custom of this.config.customPatterns ?? []) {
      const re = typeof custom.regex === "string"
        ? new RegExp(custom.regex, "g")
        : new RegExp(custom.regex.source, custom.regex.flags.includes("g") ? custom.regex.flags : custom.regex.flags + "g");

      let match;
      while ((match = re.exec(text)) !== null) {
        const value = match[0];
        if (seen.has(`${match.index}-${value}`)) continue;
        seen.add(`${match.index}-${value}`);

        const token = this.getOrCreateToken("CUSTOM" as EntityType, value, custom.category);
        entities.push({
          type: "CUSTOM",
          value,
          token,
          start: match.index,
          end: match.index + value.length,
        });
      }
    }

    for (const forcedValue of this.config.force ?? []) {
      let idx = -1;
      while ((idx = text.indexOf(forcedValue, idx + 1)) !== -1) {
        if (!seen.has(`${idx}-${forcedValue}`)) {
          seen.add(`${idx}-${forcedValue}`);
          const token = this.getOrCreateToken("CUSTOM", forcedValue, "FORCED");
          entities.push({
            type: "CUSTOM",
            value: forcedValue,
            token,
            start: idx,
            end: idx + forcedValue.length,
          });
        }
      }
    }

    return entities.sort((a, b) => a.start - b.start);
  }

  pseudonymize(text: string): { result: string; entities: DetectedEntity[] } {
    const allEntities = this.detect(text);
    const used: DetectedEntity[] = [];
    for (const entity of allEntities) {
      const overlaps = used.some(e => e.start < entity.end && entity.start < e.end);
      if (!overlaps) used.push(entity);
    }

    let result = text;
    let offset = 0;
    for (const entity of used.sort((a, b) => a.start - b.start)) {
      const start = entity.start + offset;
      const end = entity.end + offset;
      result = result.slice(0, start) + entity.token + result.slice(end);
      offset += entity.token.length - entity.value.length;
    }

    return { result, entities: used };
  }

  rehydrate(text: string): string {
    let result = text;
    for (const [token, value] of this.reverseVault.entries()) {
      result = result.replaceAll(token, value);
    }
    return result;
  }

  rehydrateChunk(chunk: string, buffer: string): { output: string; buffer: string } {
    const combined = buffer + chunk;
    const tokenPrefixMatch = combined.match(/[A-Z_]+_\d*$/);
    const newBuffer = tokenPrefixMatch ? tokenPrefixMatch[0] : "";
    const toProcess = newBuffer ? combined.slice(0, -newBuffer.length) : combined;

    return {
      output: this.rehydrate(toProcess),
      buffer: newBuffer,
    };
  }

  private getOrCreateToken(type: EntityType, value: string, category?: string): string {
    const existing = this.vault.get(value);
    if (existing) return existing;

    const label = category ?? type;
    const count = (this.counters.get(label) ?? 0) + 1;
    this.counters.set(label, count);

    const token = `${label}_${count}`;
    this.vault.set(value, token);
    this.reverseVault.set(token, value);
    return token;
  }

  exportVault(): Record<string, string> {
    return Object.fromEntries(this.vault);
  }

  importVault(data: Record<string, string>): void {
    for (const [value, token] of Object.entries(data)) {
      this.vault.set(value, token);
      this.reverseVault.set(token, value);

      const parts = token.split("_");
      const num = parseInt(parts[parts.length - 1], 10);
      const label = parts.slice(0, -1).join("_");
      if (!isNaN(num)) {
        const current = this.counters.get(label) ?? 0;
        this.counters.set(label, Math.max(current, num));
      }
    }
  }

  getVaultSize(): number {
    return this.vault.size;
  }
}

export interface AuditConfig {
  auditDir?: string;
  enabled?: boolean;
}

export class AuditLogger {
  private config: AuditConfig;

  constructor(config: AuditConfig = {}) {
    this.config = { enabled: true, auditDir: "./audit", ...config };
    if (this.config.enabled && this.config.auditDir) {
      // Ensure dir exists
    }
  }

  static generateRequestId(): string {
    return `req_${Date.now()}_${randomBytes(4).toString("hex")}`;
  }

  log(entry: any): void {
    if (!this.config.enabled || !this.config.auditDir) return;
    const date = new Date().toISOString().split("T")[0];
    const logPath = resolve(this.config.auditDir, `audit-${date}.jsonl`);
    try {
      appendFileSync(logPath, JSON.stringify(entry) + "\n");
    } catch (err) {
      console.error("[ShieldPipe] Audit log failed:", err);
    }
  }
}

export class MemoryVault {
  private mappings: Record<string, string> = {};
  loadMappings(): Record<string, string> { return this.mappings; }
  save(mappings: Record<string, string>): void { this.mappings = mappings; }
}

export class EncryptedVault {
  private key: Buffer;
  private path: string;

  constructor(path: string, keyMaterial: string) {
    this.path = path;
    this.key = createHash("sha256").update(keyMaterial).digest();
  }

  save(mappings: Record<string, string>): void {
    const data = JSON.stringify({
      version: 1,
      mappings,
      updated_at: new Date().toISOString(),
    });

    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    const payload = Buffer.concat([Buffer.alloc(4), iv, tag, encrypted]);
    payload.writeUInt32BE(1, 0); // version 1
    writeFileSync(this.path, payload);
  }

  loadMappings(): Record<string, string> {
    if (!existsSync(this.path)) return {};
    try {
      const raw = readFileSync(this.path);
      const version = raw.readUInt32BE(0);
      if (version !== 1) throw new Error("Unknown vault version");

      const iv = raw.slice(4, 16);
      const tag = raw.slice(16, 32);
      const encrypted = raw.slice(32);

      const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
      decipher.setAuthTag(tag);
      const decrypted = decipher.update(encrypted).toString("utf8") + decipher.final("utf8");

      return JSON.parse(decrypted).mappings;
    } catch (err) {
      console.error("[ShieldPipe] Failed to load vault:", err);
      return {};
    }
  }
}
