// Regenerate: node scripts/generate-governance-vectors.cjs /absolute/interface-bridge /absolute/koinos-bridge-contract
// Uses ethers and protobufjs, independently of the Go codec. No keys or RPCs.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const [frontend, contracts] = process.argv.slice(2);
assert(path.isAbsolute(frontend) && path.isAbsolute(contracts));
const deps = createRequire(path.join(frontend, 'package.json'));
const { utils } = deps('ethers');
const protobuf = deps('protobufjs');
const base58Module = deps('bs58');
const base58 = base58Module.default || base58Module;
const protoSource = fs.readFileSync(path.join(contracts, 'assembly/proto/bridge.proto'), 'utf8');
const schema = protobuf.parse(protoSource.replace(/import "koinos\/options.proto";/g, '').replace(/\[\(koinos\.btype\) = [A-Z_]+\]/g, '')).root;
const actions = ['add_validator', 'remove_validator', 'add_token', 'remove_token', 'add_wrapped_token', 'remove_wrapped_token', 'set_pause', null, 'set_fee_token', 'set_fee_wrapped_token', 'claim_fee_token', 'claim_fee_wrapped_token'];
const profiles = [
  { schemaVersion: 1, id: 'fixture-evm', name: 'Fixture EVM', family: 'evm', environment: 'local', networkId: '31337', bridgeChainId: 2, contract: '0x1111111111111111111111111111111111111111', codec: 'evm-1e82614-v1', sourceCommit: '1e82614bdb61a36aa3309e97001666cf1e14f7d1', codeHash: '', reviewEvidence: '', reviewed: false },
  { schemaVersion: 1, id: 'fixture-koinos', name: 'Fixture Koinos', family: 'koinos', environment: 'local', networkId: 'EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==', bridgeChainId: 1, contract: '1aqHtNRDkiAZeFtuM8fRFuurcje6eHqF8', codec: 'koinos-f7a499e-v1', sourceCommit: 'f7a499e51fe54406deb30788df526b39caead1c4', codeHash: '', reviewEvidence: '', reviewed: false },
];
const vectors = [];
for (const p of profiles) for (const [index, kind] of actions.entries()) {
  const id = index + 1;
  if (!kind || (p.family === 'koinos' && id === 12)) continue;
  for (const pause of id === 7 ? [true, false] : [undefined]) {
    const feeAction = [9, 10].includes(id) || (p.family === 'evm' && [3, 5].includes(id));
    const a = { kind, nonce: '9007199254740993', expiration: '2000000000000' };
    const target = p.family === 'evm' ? '0x2222222222222222222222222222222222222222' : '15DJN4a8SgrbGhhGksSBASiSYjGnMU8dGL';
    if (id === 7) a.pause = pause; else a.address = target;
    if (feeAction) a.fee = '18446744073709551615';
    if (id >= 11) a.wallet = target;
    let preimage, digest;
    if (p.family === 'evm') {
      const types = ['uint256', id === 7 ? 'bool' : 'address'];
      const values = [id, id === 7 ? pause : target];
      if (feeAction) { types.push('uint256'); values.push(a.fee); }
      if (id >= 11) { types.push('address'); values.push(target); }
      types.push('uint256', 'address', 'uint256', 'uint32'); values.push(a.nonce, p.contract, a.expiration, p.bridgeChainId);
      preimage = utils.solidityPack(types, values).slice(2);
      digest = utils.hashMessage(utils.arrayify(utils.keccak256('0x' + preimage))).slice(2);
    } else {
      const typeName = id === 7 ? 'set_pause_action_hash' : feeAction ? 'set_fee_hash' : id >= 11 ? 'claim_fee_hash' : 'add_remove_action_hash';
      const type = schema.lookupType('bridge.' + typeName);
      const fields = { action: id, address: base58.decode(target), token: base58.decode(target), wallet: base58.decode(target), pause, fee: a.fee, nonce: a.nonce, contractId: base58.decode(p.contract), expiration: a.expiration, chain: p.bridgeChainId };
      // sdk-as generated encoders omit proto3 defaults. protobufjs otherwise
      // encodes an explicitly present false, producing a different preimage.
      if (fields.pause === false) delete fields.pause;
      preimage = Buffer.from(type.encode(type.fromObject(fields)).finish()).toString('hex');
      digest = crypto.createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex');
    }
    vectors.push({ profile: p, action: a, preimage, digest });
  }
}
const output = { generators: { ethers: deps('ethers').version, protobufjs: deps('protobufjs/package.json').version, protoSHA256: crypto.createHash('sha256').update(protoSource).digest('hex') }, vectors };
fs.writeFileSync(path.join(__dirname, '../internal/operator/testdata/governance.json'), JSON.stringify(output, null, 2) + '\n');
console.log(`Generated ${vectors.length} independent governance vectors.`);
