// Random bytes from cryptographic-primitives, as hex (message IDs, MIME boundaries, queue IDs)

import { random_bytes_sync } from 'cryptographic-primitives/random.js';

function randomHex(n) {
  return Buffer.from(random_bytes_sync(n)).toString('hex');
}

export { randomHex };
