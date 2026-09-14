// Synthetic empty chains for local observation-worker UI checks. No transactions,
// account credentials, real chain IDs or state-changing RPC methods are exposed.
const http = require('node:http');
const server = http.createServer((req, res) => {
  let text = '';
  req.on('data', (chunk) => { text += chunk; if (text.length > 65536) req.destroy(); });
  req.on('end', () => {
    try {
      const request = JSON.parse(text);
      let result;
      if (request.method === 'eth_blockNumber') result = '0x0';
      else if (request.method === 'chain.get_head_info') result = { last_irreversible_block: '0', head_topology: { height: '0', id: '0x1220' + '00'.repeat(32) } };
      else { res.writeHead(403); res.end(JSON.stringify({ error: 'Synthetic fixture rejects this RPC method' })); return; }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
    } catch { res.writeHead(400); res.end(); }
  });
});
server.listen(18546, '127.0.0.1', () => console.log('Synthetic observation worker RPC: http://127.0.0.1:18546'));
