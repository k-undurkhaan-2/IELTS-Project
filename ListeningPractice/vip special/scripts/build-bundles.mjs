const canonicalCommand = 'node scripts/build-bundles.mjs --profile vip --output-root "ListeningPractice/vip special"';

console.error('This legacy VIP-local bundle builder is disabled.');
console.error(`Run the canonical root builder instead: ${canonicalCommand}`);
process.exitCode = 1;
