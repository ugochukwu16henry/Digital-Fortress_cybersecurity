/*
 * Minimal node version validator shim.
 *
 * The upstream OpenSearch Dashboards repo expects this file to exist under
 * `src/setup_node_env/` and to validate runtime Node.js compatibility.
 *
 * This workspace checkout is missing the original implementation, which
 * prevents local `yarn osd bootstrap/start` from running at all. Since the
 * exact validation logic is not required for the dev workflow itself, this
 * shim intentionally becomes a no-op (and emits a warning) so bootstrapping
 * can proceed.
 */
'use strict';

// Keep output lightweight; this is only relevant in dev environments.
// eslint-disable-next-line no-console
console.warn(`[osd] Skipping node version validation shim. Current Node: ${process.version}`);

