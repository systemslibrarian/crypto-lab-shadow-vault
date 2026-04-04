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
    initialized = true;
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
          break;

        case 'get_max_message_length':
          result = get_max_message_length(args.containerSize);
          break;

        default:
          self.postMessage({ id, error: `Unknown command: ${command}` });
          return;
      }
      self.postMessage({ id, result });
    } catch (err) {
      self.postMessage({
        id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, 0);
};

startup();
