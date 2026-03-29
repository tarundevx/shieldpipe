/**
 * ShieldPipe Node.js Middleware
 * Drop-in PII protection for OpenAI-compatible APIs
 * Works with Express, Fastify, and as a raw fetch wrapper
 */

import {
  PIIDetector,
  DetectionConfig,
  DetectedEntity,
  EncryptedVault,
  MemoryVault,
  AuditLogger,
  AuditConfig,
} from "./detector";

export interface ShieldPipeConfig {
  /** Detection rules */
  detection?: Partial<DetectionConfig>;
  /** Vault for persistent mappings. Pass false to disable persistence. */
  vault?: { path: string; keyEnv?: string; key?: string } | false;
  /** Audit logging config */
  audit?: Partial<AuditConfig> | false;
  /** Called after pseudonymization - useful for debugging */
  onRedact?: (entities: DetectedEntity[], requestId: string) => void;
}

export interface ShieldedResult {
  text: string;
  entities: DetectedEntity[];
  requestId: string;
  rehydrate: (response: string) => string;
}

export class ShieldPipe {
  private detector: PIIDetector;
  private vault: EncryptedVault | MemoryVault | null;
  private logger: AuditLogger | null;
  private config: ShieldPipeConfig;

  constructor(config: ShieldPipeConfig = {}) {
    this.config = config;

    // Set up vault
    if (config.vault === false) {
      this.vault = null;
    } else if (config.vault) {
      const keyMaterial =
        config.vault.key ??
        (config.vault.keyEnv ? process.env[config.vault.keyEnv] : undefined) ??
        process.env.SHIELDPIPE_VAULT_KEY;

      if (!keyMaterial) {
        console.warn(
          "[ShieldPipe] No vault key provided. Using in-memory vault (mappings will not persist)."
        );
        this.vault = new MemoryVault();
      } else {
        this.vault = new EncryptedVault(config.vault.path, keyMaterial);
      }
    } else {
      this.vault = new MemoryVault();
    }

    // Initialize detector, loading any existing mappings
    this.detector = new PIIDetector(config.detection ?? {});
    if (this.vault) {
      this.detector.importVault(this.vault.loadMappings());
    }

    // Set up audit logger
    if (config.audit === false) {
      this.logger = null;
    } else {
      this.logger = new AuditLogger(config.audit ?? {});
    }
  }

  /**
   * Pseudonymize a text string
   */
  shield(text: string): ShieldedResult {
    const requestId = AuditLogger.generateRequestId();
    const start = Date.now();

    const { result, entities } = this.detector.pseudonymize(text);

    // Persist vault
    if (this.vault) {
      this.vault.save(this.detector.exportVault());
    }

    // Fire onRedact hook
    if (entities.length > 0 && this.config.onRedact) {
      this.config.onRedact(entities, requestId);
    }

    // Audit log
    if (this.logger) {
      const typeCounts: Record<string, number> = {};
      for (const e of entities) {
        typeCounts[e.type] = (typeCounts[e.type] ?? 0) + 1;
      }
      this.logger.log({
        timestamp: new Date().toISOString(),
        requestId,
        direction: "inbound",
        entityCount: entities.length,
        entityTypes: typeCounts,
        latencyMs: Date.now() - start,
      });
    }

    return {
      text: result,
      entities,
      requestId,
      rehydrate: (response: string) => this.detector.rehydrate(response),
    };
  }

  /**
   * Wrap OpenAI-compatible fetch calls transparently
   */
  wrapFetch(originalFetch = fetch) {
    return async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      let shielded: ShieldedResult | null = null;

      // Intercept request body
      if (init?.body && typeof init.body === "string") {
        try {
          const body = JSON.parse(init.body);

          // Handle chat completions
          if (body.messages && Array.isArray(body.messages)) {
            body.messages = body.messages.map((msg: { role: string; content: string }) => {
              if (typeof msg.content === "string") {
                shielded = this.shield(msg.content);
                return { ...msg, content: shielded.text };
              }
              return msg;
            });
            init = { ...init, body: JSON.stringify(body) };
          }

          // Handle embeddings
          if (body.input && typeof body.input === "string") {
            shielded = this.shield(body.input);
            body.input = shielded.text;
            init = { ...init, body: JSON.stringify(body) };
          }
        } catch {
          // Not JSON — shield raw body
          if (init.body && typeof init.body === "string") {
            shielded = this.shield(init.body);
            init = { ...init, body: shielded.text };
          }
        }
      }

      const response = await originalFetch(url, init);

      // Rehydrate response if we redacted anything
      if (shielded && response.ok) {
        const text = await response.text();
        const rehydrated = shielded.rehydrate(text);

        return new Response(rehydrated, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      }

      return response;
    };
  }

  /**
   * Express/Connect middleware
   */
  expressMiddleware() {
    return (req: any, res: any, next: () => void) => {
      if (!req.body) return next();

      const process = (text: string): string => {
        const shielded = this.shield(text);
        res.locals._shieldpipe = shielded;
        return shielded.text;
      };

      if (typeof req.body === "string") {
        req.body = process(req.body);
      } else if (req.body?.messages) {
        req.body.messages = req.body.messages.map((m: any) => ({
          ...m,
          content: typeof m.content === "string" ? process(m.content) : m.content,
        }));
      } else if (req.body?.input && typeof req.body.input === "string") {
        req.body.input = process(req.body.input);
      }

      // Wrap res.json to rehydrate on the way out
      const originalJson = res.json.bind(res);
      res.json = (body: any) => {
        if (res.locals._shieldpipe) {
          const str = JSON.stringify(body);
          const rehydrated = res.locals._shieldpipe.rehydrate(str);
          return originalJson(JSON.parse(rehydrated));
        }
        return originalJson(body);
      };

      next();
    };
  }

  getDetector(): PIIDetector {
    return this.detector;
  }
}

// Convenience factory
export function createShield(config?: ShieldPipeConfig): ShieldPipe {
  return new ShieldPipe(config);
}

export { PIIDetector, DetectionConfig, DetectedEntity, EncryptedVault, MemoryVault };
