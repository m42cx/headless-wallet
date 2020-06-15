/* jslint node: true */

'use strict';

exports.bServeAsHub = false;
exports.bLight = false;


exports.storage = 'sqlite';

exports.WS_PROTOCOL = 'wss://';
exports.hub = 'hub.caixapay.com';
exports.deviceName = 'Headless Wallet';
exports.permanent_pairing_secret = 'randomstring';
exports.control_addresses = ['DEVICE ALLOWED TO CHAT'];
exports.payout_address = 'WHERE THE MONEY CAN BE SENT TO';
exports.KEYS_FILENAME = 'keys.json';
exports.WALLET_PASSWORD= '';
// where logs are written to (absolute path).  Default is log.txt in app data directory
// exports.LOG_FILENAME = '/dev/null';

// consolidate unspent outputs when there are too many of them.  Value of 0 means do not try to consolidate
exports.MAX_UNSPENT_OUTPUTS = 0;
exports.CONSOLIDATION_INTERVAL = 3600 * 1000;

// this is for runnining RPC service on dagly, see play/rpc_service.js
exports.rpcInterface = '127.0.0.1';
exports.rpcPort = '6332';

console.log('finished headless conf');

// Whether to redirect the output stream to a log file
exports.PIPE_OUTPUT_TO_FILE = false;
// Whether to use a password from the configuration file instead of asking it from the user
exports.INTERACT_WITH_USER = true;
// Wallet password. Relevant only in case INTERACT_WITH_USER is false.
// exports.WALLET_PASSWORD = 'BSh5COP5ZesCgmZPyPmB'; // Mock password.
