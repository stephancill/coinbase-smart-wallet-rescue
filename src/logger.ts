/**
 * Simple logger with debug/info levels.
 * Debug logs are only shown when DEBUG env var is set.
 */

const isDebug = !!process.env.DEBUG;

export const logger = {
  /**
   * Log info messages (always shown)
   */
  info: (...args: unknown[]) => {
    console.log(...args);
  },

  /**
   * Log debug messages (only shown when DEBUG env var is set)
   */
  debug: (...args: unknown[]) => {
    if (isDebug) {
      console.log("[DEBUG]", ...args);
    }
  },

  /**
   * Log warning messages (always shown)
   */
  warn: (...args: unknown[]) => {
    console.log("⚠️ ", ...args);
  },

  /**
   * Log error messages (always shown)
   */
  error: (...args: unknown[]) => {
    console.error("❌", ...args);
  },
};
