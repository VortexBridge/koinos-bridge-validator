// Independent Node/OpenSSL implementation used only with disposable test keys.
const crypto = require('node:crypto');
let input = '';
process.stdin.on('data', b => { input += b; if (input.length > 65536) process.exit(2); });
process.stdin.on('end', () => {
  const { encrypted, raw, password } = JSON.parse(input);
  const file = Buffer.from(encrypted, 'hex');
  const magic = Buffer.from('VORTEX-KEYS-V1\0');
  if (file.length !== magic.length + 32 + 12 + 64 + 16 || !file.subarray(0, magic.length).equals(magic)) process.exit(3);
  const headerSize = magic.length + 32 + 12;
  const derive = salt => crypto.scryptSync(password, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 268435456 });
  const key = derive(file.subarray(magic.length, magic.length + 32));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, file.subarray(magic.length + 32, headerSize));
  decipher.setAAD(file.subarray(0, headerSize));
  decipher.setAuthTag(file.subarray(-16));
  const plaintext = Buffer.concat([decipher.update(file.subarray(headerSize, -16)), decipher.final()]);
  if (!plaintext.equals(Buffer.from(raw, 'hex'))) process.exit(4);
  const salt = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const header = Buffer.concat([magic, salt, nonce]);
  const cipher = crypto.createCipheriv('aes-256-gcm', derive(salt), nonce);
  cipher.setAAD(header);
  process.stdout.write(Buffer.concat([header, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]).toString('hex'));
  plaintext.fill(0); key.fill(0);
});
