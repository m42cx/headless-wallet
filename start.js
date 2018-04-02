/* jslint node: true */

'use strict';

const fs = require('fs');
const crypto = require('crypto');
const util = require('util');
const constants = require('core/constants.js');
const conf = require('core/conf.js');
const objectHash = require('core/object_hash.js');
const desktopApp = require('core/desktop_app.js');
const db = require('core/db.js');
const eventBus = require('core/event_bus.js');
const ecdsaSig = require('core/signature.js');
const Mnemonic = require('bitcore-mnemonic');
const Bitcore = require('bitcore-lib');
const readline = require('readline');

const appDataDir = desktopApp.getAppDataDir();
const KEYS_FILENAME = `${appDataDir}/${conf.KEYS_FILENAME || 'keys.json'}`;
let wallet_id;
let xPrivKey;

function replaceConsoleLog() {
    if (conf.PIPE_OUTPUT_TO_FILE) {
        const log_filename = conf.LOG_FILENAME || (`${appDataDir}/log.txt`);
        const writeStream = fs.createWriteStream(log_filename);
        console.log('---------------');
        console.log(`From this point, output will be redirected to ${log_filename}`);
        console.log("To release the terminal, type Ctrl-Z, then 'bg'");
        console.log = function () {
            writeStream.write(`${Date().toString()}: `);
            writeStream.write(`${util.format.apply(null, arguments)}\n`);
        };
        console.warn = console.log;
        console.info = console.log;
    }
}

function askForInteractiveConfiguration(rl, question, configValue) {
    if (!conf.INTERACT_WITH_USER) {
        return Promise.resolve(configValue);
    }

    return new Promise((resolve) => {
        rl.question(question, (userInput) => {
            resolve(userInput);
        });
    });
}

function readKeys(onDone) {
    console.log('-----------------------');
    if (conf.control_addresses) { console.log(`remote access allowed from devices: ${conf.control_addresses.join(', ')}`); }
    if (conf.payout_address) { console.log(`payouts allowed to address: ${conf.payout_address}`); }
    console.log('-----------------------');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
        // terminal: true
    });
    fs.readFile(KEYS_FILENAME, 'utf8', (err, data) => {
        if (err) { // first start
            console.log('failed to read keys, will gen');
            const suggestedDeviceName = require('os').hostname() || 'Headless';
            const userConfFile = `${appDataDir}/conf.json`;

            askForInteractiveConfiguration(rl, `Please name this device [${suggestedDeviceName}]: `, conf.deviceName).then((deviceName) => {
                if (!deviceName) { deviceName = suggestedDeviceName; }

                return new Promise((resolve, reject) => {
                    fs.writeFile(userConfFile, JSON.stringify({ deviceName }, null, '\t'), 'utf8', (err) => {
                        if (err) {
                            reject(`failed to write conf.json: ${err}`);
                        } else {
                            resolve();
                        }
                    });
                });
            }).then(() => askForInteractiveConfiguration(
                    rl,
                    `Device name saved to ${userConfFile}, you can edit it later if you like.\n\nPassphrase for your private keys: `,
                    conf.WALLET_PASSWORD
                )).then((passphrase) => {
                rl.close();
                if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
                if (process.stdout.clearLine) process.stdout.clearLine();
                const deviceTempPrivKey = crypto.randomBytes(32);
                const devicePrevTempPrivKey = crypto.randomBytes(32);

                let mnemonic = new Mnemonic(); // generates new mnemonic
                while (!Mnemonic.isValid(mnemonic.toString())) { mnemonic = new Mnemonic(); }

                writeKeys(mnemonic.phrase, deviceTempPrivKey, devicePrevTempPrivKey, () => {
                    console.log('keys created');
                    const xPrivKey = mnemonic.toHDPrivateKey(passphrase);
                    createWallet(xPrivKey, () => {
                        onDone(mnemonic.phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey);
                    });
                });
            });
        } else { // 2nd or later start
            return askForInteractiveConfiguration(
                rl,
                'Passphrase: ',
                conf.WALLET_PASSWORD
            ).then((passphrase) => {
                rl.close();
                if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
                if (process.stdout.clearLine) process.stdout.clearLine();
                const keys = JSON.parse(data);
                const deviceTempPrivKey = Buffer(keys.temp_priv_key, 'base64');
                const devicePrevTempPrivKey = Buffer(keys.prev_temp_priv_key, 'base64');
                determineIfWalletExists((bWalletExists) => {
                    if (bWalletExists) { onDone(keys.mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey); } else {
                        const mnemonic = new Mnemonic(keys.mnemonic_phrase);
                        const xPrivKey = mnemonic.toHDPrivateKey(passphrase);
                        createWallet(xPrivKey, () => {
                            onDone(keys.mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey);
                        });
                    }
                });
            });
        }
    });
}

function writeKeys(mnemonic_phrase, deviceTempPrivKey, devicePrevTempPrivKey, onDone) {
    const keys = {
        mnemonic_phrase,
        temp_priv_key: deviceTempPrivKey.toString('base64'),
        prev_temp_priv_key: devicePrevTempPrivKey.toString('base64')
    };
    fs.writeFile(KEYS_FILENAME, JSON.stringify(keys, null, '\t'), 'utf8', (err) => {
        if (err) { throw Error('failed to write keys file'); }
        if (onDone) { onDone(); }
    });
}

function createWallet(xPrivKey, onDone) {
    const devicePrivKey = xPrivKey.derive("m/1'").privateKey.bn.toBuffer({ size: 32 });
    const device = require('core/device.js');
    device.setDevicePrivateKey(devicePrivKey); // we need device address before creating a wallet
    const strXPubKey = Bitcore.HDPublicKey(xPrivKey.derive("m/44'/0'/0'")).toString();
    const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
    // we pass isSingleAddress=false because this flag is meant to be forwarded to cosigners and headless wallet doesn't support multidevice
    walletDefinedByKeys.createWalletByDevices(strXPubKey, 0, 1, [], 'any walletName', false, (wallet_id) => {
        walletDefinedByKeys.issueNextAddress(wallet_id, 0, (addressInfo) => {
            onDone();
        });
    });
}

function isControlAddress(device_address) {
    return (conf.control_addresses && conf.control_addresses.indexOf(device_address) >= 0);
}

function readSingleAddress(handleAddress) {
    db.query('SELECT address FROM my_addresses WHERE wallet=?', [wallet_id], (rows) => {
        if (rows.length === 0) { throw Error('no addresses'); }
        if (rows.length > 1) { throw Error('more than 1 address'); }
        handleAddress(rows[0].address);
    });
}

function readFirstAddress(handleAddress) {
    db.query('SELECT address FROM my_addresses WHERE wallet=? AND address_index=0 AND is_change=0', [wallet_id], (rows) => {
        if (rows.length === 0) { throw Error('no addresses'); }
        if (rows.length > 1) { throw Error('more than 1 address'); }
        handleAddress(rows[0].address);
    });
}

function prepareBalanceText(handleBalanceText) {
    const Wallet = require('core/wallet.js');
    Wallet.readBalance(wallet_id, (assocBalances) => {
        const arrLines = [];
        for (const asset in assocBalances) {
            const total = assocBalances[asset].stable + assocBalances[asset].pending;
            const units = (asset === 'base') ? ' bytes' : (` of ${asset}`);
            let line = total + units;
            if (assocBalances[asset].pending) { line += ` (${assocBalances[asset].pending} pending)`; }
            arrLines.push(line);
        }
        handleBalanceText(arrLines.join('\n'));
    });
}

function readSingleWallet(handleWallet) {
    db.query('SELECT wallet FROM wallets', (rows) => {
        if (rows.length === 0) { throw Error('no wallets'); }
        if (rows.length > 1) { throw Error('more than 1 wallet'); }
        handleWallet(rows[0].wallet);
    });
}

function determineIfWalletExists(handleResult) {
    db.query('SELECT wallet FROM wallets', (rows) => {
        if (rows.length > 1) { throw Error('more than 1 wallet'); }
        handleResult(rows.length > 0);
    });
}

function signWithLocalPrivateKey(wallet_id, account, is_change, address_index, text_to_sign, handleSig) {
    const path = `m/44'/0'/${account}'/${is_change}/${address_index}`;
    const privateKey = xPrivKey.derive(path).privateKey;
    const privKeyBuf = privateKey.bn.toBuffer({ size: 32 }); // https://github.com/bitpay/bitcore-lib/issues/47
    handleSig(ecdsaSig.sign(text_to_sign, privKeyBuf));
}

const signer = {
    readSigningPaths(conn, address, handleLengthsBySigningPaths) {
        handleLengthsBySigningPaths({ r: constants.SIG_LENGTH });
    },
    readDefinition(conn, address, handleDefinition) {
        conn.query('SELECT definition FROM my_addresses WHERE address=?', [address], (rows) => {
            if (rows.length !== 1) { throw Error('definition not found'); }
            handleDefinition(null, JSON.parse(rows[0].definition));
        });
    },
    sign(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature) {
        const buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
        db.query(
            'SELECT wallet, account, is_change, address_index \n\
            FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
            WHERE address=? AND signing_path=?',
            [address, signing_path],
            (rows) => {
                if (rows.length !== 1) { throw Error(`${rows.length} indexes for address ${address} and signing path ${signing_path}`); }
                const row = rows[0];
                signWithLocalPrivateKey(row.wallet, row.account, row.is_change, row.address_index, buf_to_sign, (sig) => {
                    handleSignature(null, sig);
                });
            }
        );
    }
};


if (conf.permanent_pairing_secret) {
 db.query(
        `INSERT ${db.getIgnore()} INTO pairing_secrets (pairing_secret, is_permanent, expiry_date) VALUES (?, 1, '2038-01-01')`,
        [conf.permanent_pairing_secret]
    );
}

setTimeout(() => {
    readKeys((mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey) => {
        const saveTempKeys = function (new_temp_key, new_prev_temp_key, onDone) {
            writeKeys(mnemonic_phrase, new_temp_key, new_prev_temp_key, onDone);
        };
        const mnemonic = new Mnemonic(mnemonic_phrase);
        // global
        xPrivKey = mnemonic.toHDPrivateKey(passphrase);
        const devicePrivKey = xPrivKey.derive("m/1'").privateKey.bn.toBuffer({ size: 32 });
        // read the id of the only wallet
        readSingleWallet((wallet) => {
            // global
            wallet_id = wallet;
            const device = require('core/device.js');
            device.setDevicePrivateKey(devicePrivKey);
            const my_device_address = device.getMyDeviceAddress();
            db.query('SELECT 1 FROM extended_pubkeys WHERE device_address=?', [my_device_address], (rows) => {
                if (rows.length > 1) { throw Error('more than 1 extended_pubkey?'); }
                if (rows.length === 0) {
return setTimeout(() => {
                        console.log('passphrase is incorrect');
                        process.exit(0);
                    }, 1000);
}
                require('core/wallet.js'); // we don't need any of its functions but it listens for hub/* messages
                device.setTempKeys(deviceTempPrivKey, devicePrevTempPrivKey, saveTempKeys);
                device.setDeviceName(conf.deviceName);
                device.setDeviceHub(conf.hub);
                const my_device_pubkey = device.getMyDevicePubKey();
                console.log(`====== my device address: ${my_device_address}`);
                console.log(`====== my device pubkey: ${my_device_pubkey}`);
                if (conf.permanent_pairing_secret) { console.log(`====== my pairing code: ${my_device_pubkey}@${conf.hub}#${conf.permanent_pairing_secret}`); }
                if (conf.bLight) {
                    const light_wallet = require('core/light_wallet.js');
                    light_wallet.setLightVendorHost(conf.hub);
                }
                eventBus.emit('headless_wallet_ready');
                setTimeout(replaceConsoleLog, 1000);
                if (conf.MAX_UNSPENT_OUTPUTS && conf.CONSOLIDATION_INTERVAL) {
                    const consolidation = require('./consolidation.js');
                    const network = require('core/network.js');
                    function consolidate() {
                        if (!network.isCatchingUp()) { consolidation.consolidate(wallet_id, signer); }
                    }
                    setInterval(consolidate, conf.CONSOLIDATION_INTERVAL);
                    setTimeout(consolidate, 300 * 1000);
                }
            });
        });
    });
}, 1000);


function handlePairing(from_address) {
    const device = require('core/device.js');
    prepareBalanceText((balance_text) => {
        device.sendMessageToDevice(from_address, 'text', balance_text);
    });
}

function sendPayment(asset, amount, to_address, change_address, device_address, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    Wallet.sendPaymentFromWallet(
        asset, wallet_id, to_address, amount, change_address,
        [], device_address,
        signWithLocalPrivateKey,
        (err, unit, assocMnemonics) => {
            if (device_address) {
                if (err) { device.sendMessageToDevice(device_address, 'text', `Failed to pay: ${err}`); }
                // else
                // if successful, the peer will also receive a payment notification
                //	device.sendMessageToDevice(device_address, 'text', "paid");
            }
            if (onDone) { onDone(err, unit, assocMnemonics); }
        }
    );
}

function sendMultiPayment(opts, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    if (!opts.paying_addresses) { opts.wallet = wallet_id; }
    opts.arrSigningDeviceAddresses = [device.getMyDeviceAddress()];
    opts.signWithLocalPrivateKey = signWithLocalPrivateKey;
    Wallet.sendMultiPayment(opts, (err, unit, assocMnemonics) => {
        if (onDone) { onDone(err, unit, assocMnemonics); }
    });
}

function sendPaymentUsingOutputs(asset, outputs, change_address, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    const opt = {
        asset,
        wallet: wallet_id,
        change_address,
        arrSigningDeviceAddresses: [device.getMyDeviceAddress()],
        recipient_device_address: null,
        signWithLocalPrivateKey
    };
    if (asset === 'base' || asset === null) {
        opt.base_outputs = outputs;
    } else {
        opt.asset_outputs = outputs;
    }
    Wallet.sendMultiPayment(opt, (err, unit, assocMnemonics) => {
        if (onDone) { onDone(err, unit, assocMnemonics); }
    });
}

function sendAllBytes(to_address, recipient_device_address, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    Wallet.sendMultiPayment({
        asset: null,
        to_address,
        send_all: true,
        wallet: wallet_id,
        arrSigningDeviceAddresses: [device.getMyDeviceAddress()],
        recipient_device_address,
        signWithLocalPrivateKey
    }, (err, unit, assocMnemonics) => {
        if (onDone) { onDone(err, unit, assocMnemonics); }
    });
}

function sendAllBytesFromAddress(from_address, to_address, recipient_device_address, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    Wallet.sendMultiPayment({
        asset: null,
        to_address,
        send_all: true,
        paying_addresses: [from_address],
        arrSigningDeviceAddresses: [device.getMyDeviceAddress()],
        recipient_device_address,
        signWithLocalPrivateKey
    }, (err, unit, assocMnemonics) => {
        if (onDone) { onDone(err, unit, assocMnemonics); }
    });
}

function sendAssetFromAddress(asset, amount, from_address, to_address, recipient_device_address, onDone) {
    const device = require('core/device.js');
    const Wallet = require('core/wallet.js');
    Wallet.sendMultiPayment({
        fee_paying_wallet: wallet_id,
        asset,
        to_address,
        amount,
        paying_addresses: [from_address],
        change_address: from_address,
        arrSigningDeviceAddresses: [device.getMyDeviceAddress()],
        recipient_device_address,
        signWithLocalPrivateKey
    }, (err, unit, assocMnemonics) => {
        if (onDone) { onDone(err, unit, assocMnemonics); }
    });
}

function issueChangeAddressAndSendPayment(asset, amount, to_address, device_address, onDone) {
    issueChangeAddress((change_address) => {
        sendPayment(asset, amount, to_address, change_address, device_address, onDone);
    });
}

function issueChangeAddressAndSendMultiPayment(opts, onDone) {
    issueChangeAddress((change_address) => {
        opts.change_address = change_address;
        sendMultiPayment(opts, onDone);
    });
}

function issueOrSelectNextMainAddress(handleAddress) {
    const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
    walletDefinedByKeys.issueOrSelectNextAddress(wallet_id, 0, (objAddr) => {
        handleAddress(objAddr.address);
    });
}

function issueNextMainAddress(handleAddress) {
    const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
    walletDefinedByKeys.issueNextAddress(wallet_id, 0, (objAddr) => {
        handleAddress(objAddr.address);
    });
}

function issueOrSelectAddressByIndex(is_change, address_index, handleAddress) {
    const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
    walletDefinedByKeys.readAddressByIndex(wallet_id, is_change, address_index, (objAddr) => {
        if (objAddr) { return handleAddress(objAddr.address); }
        walletDefinedByKeys.issueAddress(wallet_id, is_change, address_index, (objAddr) => {
            handleAddress(objAddr.address);
        });
    });
}

function issueOrSelectStaticChangeAddress(handleAddress) {
    issueOrSelectAddressByIndex(1, 0, handleAddress);
}

function issueChangeAddress(handleAddress) {
    if (conf.bSingleAddress) { readSingleAddress(handleAddress); } else if (conf.bStaticChangeAddress) { issueOrSelectStaticChangeAddress(handleAddress); } else {
        const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
        walletDefinedByKeys.issueOrSelectNextChangeAddress(wallet_id, (objAddr) => {
            handleAddress(objAddr.address);
        });
    }
}

function handleText(from_address, text, onUnknown) {
    text = text.trim();
    const fields = text.split(/ /);
    const command = fields[0].trim().toLowerCase();
    const params = ['', ''];
    if (fields.length > 1) params[0] = fields[1].trim();
    if (fields.length > 2) params[1] = fields[2].trim();

    const walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
    const device = require('core/device.js');
    switch (command) {
        case 'address':
            if (conf.bSingleAddress) {
 readSingleAddress((address) => {
                    device.sendMessageToDevice(from_address, 'text', address);
                });
} else {
walletDefinedByKeys.issueOrSelectNextAddress(wallet_id, 0, (addressInfo) => {
                    device.sendMessageToDevice(from_address, 'text', addressInfo.address);
                });
}
            break;

        case 'balance':
            prepareBalanceText((balance_text) => {
                device.sendMessageToDevice(from_address, 'text', balance_text);
            });
            break;

        case 'pay':
            analyzePayParams(params[0], params[1], (asset, amount) => {
                if (asset === null && amount === null) {
                    let msg = 'syntax: pay [amount] [asset]';
                    msg +=	'\namount: digits only';
                    msg +=	"\nasset: one of '', 'bytes', 'blackbytes', ASSET_ID";
                    msg +=	'\n';
                    msg +=	"\nExample 1: 'pay 12345' pays 12345 bytes";
                    msg +=	"\nExample 2: 'pay 12345 bytes' pays 12345 bytes";
                    msg +=	"\nExample 3: 'pay 12345 blackbytes' pays 12345 blackbytes";
                    msg +=	"\nExample 4: 'pay 12345 qO2JsiuDMh/j+pqJYZw3u82O71WjCDf0vTNvsnntr8o=' pays 12345 blackbytes";
                    msg +=	"\nExample 5: 'pay 12345 ASSET_ID' pays 12345 of asset with ID ASSET_ID";
                    return device.sendMessageToDevice(from_address, 'text', msg);
                }

                if (!conf.payout_address) { return device.sendMessageToDevice(from_address, 'text', 'payout address not defined'); }

                function payout(amount, asset) {
                    if (conf.bSingleAddress) {
readSingleAddress((address) => {
                            sendPayment(asset, amount, conf.payout_address, address, from_address);
                        });
} else
                        // create a new change address or select first unused one
                        { issueChangeAddressAndSendPayment(asset, amount, conf.payout_address, from_address); }
                }

                if (asset !== null) {
                    db.query('SELECT unit FROM assets WHERE unit=?', [asset], (rows) => {
                        if (rows.length === 1) {
                            // asset exists
                            payout(amount, asset);
                        } else {
                            // unknown asset
                            device.sendMessageToDevice(from_address, 'text', `unknown asset: ${asset}`);
                        }
                    });
                } else {
                    payout(amount, asset);
                }
            });
            break;

        default:
            if (onUnknown) {
                onUnknown(from_address, text);
            } else {
                device.sendMessageToDevice(from_address, 'text', 'unrecognized command');
            }
    }
}

function analyzePayParams(amountText, assetText, cb) {
    // expected:
    // amountText = amount; only digits
    // assetText = asset; '' -> whitebytes, 'bytes' -> whitebytes, 'blackbytes' -> blackbytes, '{asset-ID}' -> any asset

    if (amountText === '' && assetText === '') return cb(null, null);

    const pattern = /^\d+$/;
    if (pattern.test(amountText)) {
        const amount = parseInt(amountText);

        const asset = assetText.toLowerCase();
        switch (asset) {
            case '':
            case 'bytes':
                return cb(null, amount);
            case 'blackbytes':
                return cb(constants.BLACKBYTES_ASSET, amount);
            default:
                // return original assetText string because asset ID it is case sensitive
                return cb(assetText, amount);
        }
    } else {
        return cb(null, null);
    }
}

// The below events can arrive only after we read the keys and connect to the hub.
// The event handlers depend on the global var wallet_id being set, which is set after reading the keys

function setupChatEventHandlers() {
    eventBus.on('paired', (from_address) => {
        console.log(`paired ${from_address}`);
        if (!isControlAddress(from_address)) { return console.log('ignoring pairing from non-control address'); }
        handlePairing(from_address);
    });

    eventBus.on('text', (from_address, text) => {
        console.log(`text from ${from_address}: ${text}`);
        if (!isControlAddress(from_address)) { return console.log('ignoring text from non-control address'); }
        handleText(from_address, text);
    });
}

exports.readSingleWallet = readSingleWallet;
exports.readSingleAddress = readSingleAddress;
exports.readFirstAddress = readFirstAddress;
exports.signer = signer;
exports.isControlAddress = isControlAddress;
exports.issueOrSelectNextMainAddress = issueOrSelectNextMainAddress;
exports.issueNextMainAddress = issueNextMainAddress;
exports.issueOrSelectAddressByIndex = issueOrSelectAddressByIndex;
exports.issueOrSelectStaticChangeAddress = issueOrSelectStaticChangeAddress;
exports.issueChangeAddressAndSendPayment = issueChangeAddressAndSendPayment;
exports.setupChatEventHandlers = setupChatEventHandlers;
exports.handlePairing = handlePairing;
exports.handleText = handleText;
exports.sendAllBytesFromAddress = sendAllBytesFromAddress;
exports.sendAssetFromAddress = sendAssetFromAddress;
exports.sendAllBytes = sendAllBytes;
exports.sendPaymentUsingOutputs = sendPaymentUsingOutputs;
exports.sendMultiPayment = sendMultiPayment;
exports.issueChangeAddressAndSendMultiPayment = issueChangeAddressAndSendMultiPayment;

if (require.main === module) { setupChatEventHandlers(); }
