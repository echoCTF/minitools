/*
 * Requires nodejs
 * How to run
 * npm install ws
 * node websockets-client.js HOST PORT MESSAGE
 * Example: send HELP to 127.0.0.1 port 12345
 * node websockets-client.js 127.0.0.1 12345 HELP
 */
const WebSocket = require('ws');
var myArgs = process.argv.slice(2);
var ipaddr=myArgs[0] || '127.0.0.1'
var port=myArgs[1] || '51337'
var wsMessage=myArgs[2] || 'help'

const ws = new WebSocket(`ws://${ipaddr}:${port}/`);

ws.on('open', function open() {
  ws.send(`${wsMessage}`);
  ws.close();
});

ws.on('message', function incoming(data) {
  console.log(data);
});
