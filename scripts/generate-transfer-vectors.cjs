// Regenerate from repository root: node scripts/generate-transfer-vectors.cjs /absolute/interface-bridge
// Independent ethers/protobufjs synthetic vectors; no keys or RPCs.
const fs=require('fs');const path=require('path');const {createRequire}=require('module');
const frontend=process.argv[2];if(!frontend||!path.isAbsolute(frontend))throw Error('absolute frontend checkout required');
const requireUI=createRequire(path.join(frontend,'package.json'));
const ethers=requireUI('ethers');const protobuf=requireUI('protobufjs');const crypto=require('crypto');
const existing=JSON.parse(fs.readFileSync('internal/operator/testdata/governance.json'));
const evm=existing.vectors.find(v=>v.profile.family==='evm').profile;
const koinos=existing.vectors.find(v=>v.profile.family==='koinos').profile;
const {utils}=requireUI('koilib');
const schema=protobuf.parse('syntax="proto3";message Transfer {uint32 action=1; bytes transaction_id=2; bytes token=3; bytes recipient=4; bytes relayer=5; uint64 amount=6; uint64 payment=7; string metadata=8; bytes contract_id=9; uint64 expiration=10; uint32 chain=11;}').root.lookupType('Transfer');
const vectors=[];
for(const p of [evm,koinos])for(const amount of ['1','9223372036854775808','18446744073709551615']){
 const t={transactionId:'12'.repeat(32),operationId:p.family==='evm'?'18446744073709551615':'0',token:p.contract,recipient:p.contract,relayer:p.contract,amount,payment:'0',metadata:'synthetic transfer',expiration:'2000000000000'};
 let digest;
 if(p.family==='evm'){
 const packed=ethers.utils.solidityKeccak256(['uint256','bytes','uint256','address','address','address','uint256','uint256','string','address','uint256','uint32'],[8,'0x'+t.transactionId,t.operationId,t.token,t.relayer,t.recipient,t.amount,t.payment,t.metadata,p.contract,t.expiration,p.bridgeChainId]);
 digest=ethers.utils.hashMessage(ethers.utils.arrayify(packed)).slice(2);
 }else{
 const payload=schema.fromObject({action:8,transactionId:Buffer.from(t.transactionId,'hex'),token:Buffer.from(utils.decodeBase58(t.token)),recipient:Buffer.from(utils.decodeBase58(t.recipient)),relayer:Buffer.from(utils.decodeBase58(t.relayer)),amount:t.amount,payment:t.payment,metadata:t.metadata,contractId:Buffer.from(utils.decodeBase58(p.contract)),expiration:t.expiration,chain:p.bridgeChainId});
 // The reviewed generated AssemblyScript and Go codecs omit proto3 defaults.
 if(t.payment==='0')delete payload.payment;
 digest=crypto.createHash('sha256').update(schema.encode(payload).finish()).digest('hex');
 }
 vectors.push({profile:p,transfer:t,digest});
}
fs.mkdirSync('internal/managed/testdata',{recursive:true});fs.writeFileSync('internal/managed/testdata/transfers.json',JSON.stringify({scope:'Independent ethers/protobufjs synthetic transfer boundary vectors',vectors},null,2)+'\n');
