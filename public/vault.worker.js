/**
 * Shadow Vault — WASM crypto Worker (ES module).
 *
 * Loads the Rust/WASM crypto core and handles all cryptographic
 * operations off the main thread. Key material never leaves WASM
 * linear memory — only passphrases, messages, and container bytes
 * cross the boundary.
 */

import init, {
  create_container,
  open_container,
  self_test,
  get_max_message_length,
} from './shadow_vault_crypto.js';

let initialized = false;

async function startup() {
  try {
    await init();
    // Run self-test as part of initialization
    const testResult = self_test();
    // Only mark initialized if self-test passes — refuse all operations otherwise
    if (testResult && testResult.passed) {
      initialized = true;
    }
    self.postMessage({ type: 'ready', selfTest: testResult });
  } catch (err) {
    self.postMessage({
      type: 'init-error',
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

self.onmessage = (e) => {
  const { id, command, args } = e.data;

  if (!initialized) {
    self.postMessage({ id, error: 'WASM not initialized' });
    return;
  }

  /**
   * Best-effort cleanup of sensitive string/buffer args after crypto
   * operations complete. JS strings are immutable and GC-managed, so
   * overwriting the property only removes the Worker-scope reference —
   * the engine may retain copies. This is defense-in-depth, not a
   * guarantee (see THREAT_MODEL.md §2.2).
   */
  function clearArgs() {
    if (args.realPassphrase !== undefined)  args.realPassphrase = '';
    if (args.decoyPassphrase !== undefined) args.decoyPassphrase = '';
    if (args.passphrase !== undefined)      args.passphrase = '';
    if (args.realMessage !== undefined)     args.realMessage = '';
    if (args.decoyMessage !== undefined)    args.decoyMessage = '';
    if (args.containerData instanceof Uint8Array) {
      args.containerData.fill(0);
    }
  }

  // Yield before blocking crypto work so the main thread
  // can display the progress indicator.
  setTimeout(() => {
    try {
      let result;
      switch (command) {
        case 'create_container':
          result = create_container(
            args.realMessage,
            args.decoyMessage,
            args.realPassphrase,
            args.decoyPassphrase,
            args.containerSize,
            args.memoryKib,
            args.iterations,
            args.parallelism,
          );
          clearArgs();
          // The container Uint8Array from WASM needs to be transferred
          // Convert to plain object for postMessage
          if (result && result.container) {
            const container = new Uint8Array(result.container);
            self.postMessage({
              id,
              result: {
                container,
                realOffset: result.realOffset,
                decoyOffset: result.decoyOffset,
                collisionResolved: result.collisionResolved,
              },
            }, [container.buffer]);
            return;
          }
          break;

        case 'open_container':
          result = open_container(
            args.containerData,
            args.passphrase,
            args.containerSize,
            args.memoryKib,
            args.iterations,
            args.parallelism,
          );
          clearArgs();
          break;

        case 'get_max_message_length':
          result = get_max_message_length(args.containerSize);
          break;

        default:
          clearArgs();
          self.postMessage({ id, error: `Unknown command: ${command}` });
          return;
      }
      self.postMessage({ id, result });
    } catch (err) {
      clearArgs();
      self.postMessage({
        id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, 0);
};

startup();
