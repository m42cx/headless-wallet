/*jslint node: true */
"use strict";
var fs = require('fs');
var crypto = require('crypto');
var conf = require('core/conf.js');
var desktopApp = require('core/desktop_app.js');
var db = require('core/db.js');
var Mnemonic = require('bitcore-mnemonic');
var readline = require('readline');
var async = require('async');

var appDataDir = desktopApp.getAppDataDir();
var KEYS_FILENAME = appDataDir + '/' + (conf.KEYS_FILENAME || 'keys.json');

function readKeys(onDone){
	console.log('-----------------------');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
        //terminal: true
    });
	fs.readFile(KEYS_FILENAME, 'utf8', function(err, data){
		if (err){ // first start
			console.log('failed to read keys, will gen');
            const userConfFile = appDataDir + '/conf.json';

            fs.writeFile(userConfFile, JSON.stringify({deviceName: 'Dagcoin Bot'}, null, '\t'), 'utf8', function (err) {
                if (err) {
                    throw err;
                } else {
                    rl.question('Passphrase for your private keys: ', function(passphrase){
                        rl.close();
                        if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
                        if (process.stdout.clearLine)  process.stdout.clearLine();
                        var deviceTempPrivKey = crypto.randomBytes(32);
                        var devicePrevTempPrivKey = crypto.randomBytes(32);

                        var mnemonic = new Mnemonic(); // generates new mnemonic
                        while (!Mnemonic.isValid(mnemonic.toString()))
                            mnemonic = new Mnemonic();

                        writeKeys(mnemonic.phrase, deviceTempPrivKey, devicePrevTempPrivKey, function(){
							onDone(mnemonic.phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey);
                        });
                    });
                }
            });
		}
		else { // 2nd or later start
            rl.question('Passphrase: ', function(passphrase){
                rl.close();
                if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
                if (process.stdout.clearLine)  process.stdout.clearLine();
                var keys = JSON.parse(data);
                var deviceTempPrivKey = Buffer(keys.temp_priv_key, 'base64');
                var devicePrevTempPrivKey = Buffer(keys.prev_temp_priv_key, 'base64');
				onDone(keys.mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey);
            });
		}
	});
}

function writeKeys(mnemonic_phrase, deviceTempPrivKey, devicePrevTempPrivKey, onDone){
	var keys = {
		mnemonic_phrase: mnemonic_phrase,
		temp_priv_key: deviceTempPrivKey.toString('base64'),
		prev_temp_priv_key: devicePrevTempPrivKey.toString('base64')
	};
	fs.writeFile(KEYS_FILENAME, JSON.stringify(keys, null, '\t'), 'utf8', function(err){
		if (err)
			throw Error("failed to write keys file");
		if (onDone)
			onDone();
	});
}

if (conf.permanent_pairing_secret)
	db.query(
		"INSERT "+db.getIgnore()+" INTO pairing_secrets (pairing_secret, is_permanent, expiry_date) VALUES (?, 1, '2038-01-01')",
		[conf.permanent_pairing_secret]
	);

function initDb(cb) {
    db.query('SELECT name FROM sqlite_master WHERE type=\'table\'', function(result) {
        var bot_wallet = result.find(function(t) { return t.name === "bot_wallets"; });
        if (!bot_wallet) {
            db.query('CREATE TABLE `bot_wallets` (\n' +
                '\t`wallet`\tCHAR ( 44 ) NOT NULL,\n' +
                '\t`number`\tINT NOT NULL,\n' +
                '\tPRIMARY KEY(`wallet`)\n' +
                ');', cb);
        } else {
            cb();
        }
    });
}

setTimeout(function() {
	initDb(function() {
        readKeys(function(mnemonic_phrase, passphrase, deviceTempPrivKey, devicePrevTempPrivKey){
            var saveTempKeys = function(new_temp_key, new_prev_temp_key, onDone){
                writeKeys(mnemonic_phrase, new_temp_key, new_prev_temp_key, onDone);
            };
            var mnemonic = new Mnemonic(mnemonic_phrase);
            // global
            var xPrivKey = mnemonic.toHDPrivateKey(passphrase);
            var devicePrivKey = xPrivKey.derive("m/1'").privateKey.bn.toBuffer({size:32});
            // read the id of the only wallet

			var device = require('core/device.js');
			device.setDevicePrivateKey(devicePrivKey);
			var my_device_address = device.getMyDeviceAddress();
			db.query("SELECT 1 FROM extended_pubkeys WHERE device_address=?", [my_device_address], function(rows){
                if (rows.length === 0)
                    return setTimeout(function(){
                        console.log('passphrase is incorrect');
                        process.exit(0);
                    }, 1000);

				require('core/wallet.js'); // we don't need any of its functions but it listens for hub/* messages
				device.setTempKeys(deviceTempPrivKey, devicePrevTempPrivKey, saveTempKeys);
				device.setDeviceName(conf.deviceName);
				device.setDeviceHub(conf.hub);

                if (conf.bLight){
                    var light_wallet = require('core/light_wallet.js');
                    light_wallet.setLightVendorHost(conf.hub);
                }

				var bot = new Bot(passphrase);
				bot.init();
            });
        });
	});
}, 1000);

//bot

function Bot(passphrase){
	var self = this;
	self.wallets = [];
	self.fee = conf.BOT_PAYMENT_FEE;

    function initWallets(cb) {
        console.log('*******init-wallets - started*******');

        var functions = [];

        var numbers = [];

		for (var i = 0; i < conf.BOT_WALLETS_COUNT; i++) {
			numbers.push(i);
		}

        numbers.forEach(function(num) {
            functions.push(function(callback) {
                var bw = require('./bot.wallet.js');
                var wallet = new bw.BotWallet();
                wallet.init(passphrase, num, function() {
                    self.wallets.push(wallet);
                    callback(null, wallet.walletId);
                });
            });
		});

		async.series(functions, function(err, results) {
			console.log('*******init-addresses - finished*******');
			console.log('errors', err);

            var device = require('core/device.js');
			console.log('***************************Device Address***************************');
			console.log(device.getMyDeviceAddress());

            db.query("SELECT address, wallet FROM my_addresses WHERE address_index=0 AND is_change=0", function(rows){
                console.log('***************************WALLETS***************************');
                results.forEach(function(w) {
                	rows.forEach(function (r) { if (r.wallet === w) {
                		console.log("Wallet: " + w + "\tAddress: " + r.address);
					}});
				});
                console.log('***************************WALLETS***************************');
                cb();
            });
		});
    }

    function getAvailableWallets(count, cb) {
        console.log('*******get-available-addresses - started*******');
        var functions = [];

        self.wallets.forEach(function(wallet) {
            functions.push(function(asyncCallback) {
                wallet.isStableAndHasAmount(self.fee, function(result) {
                    asyncCallback(null, {wallet: wallet, available: result});
                });
            });
        });

        async.series(functions, function(err, results) {
            var wallets = results.filter(function(r) {
                return r.available;
            }).map(function(r) {
                return r.wallet;
            });

            console.log("available count: ", wallets.length);
            console.log('*******get-available-addresses - finished*******');

            cb(wallets.slice(0, count));
        });
    }

    function shuffle(array) {
        var currentIndex = array.length, temporaryValue, randomIndex;

        // While there remain elements to shuffle...
        while (0 !== currentIndex) {

            // Pick a remaining element...
            randomIndex = Math.floor(Math.random() * currentIndex);
            currentIndex -= 1;

            // And swap it with the current element.
            temporaryValue = array[currentIndex];
            array[currentIndex] = array[randomIndex];
            array[randomIndex] = temporaryValue;
        }

        return array;
    }

    function runJob() {
        console.log('*******job run*******');

        setTimeout(function() {
            var paymentAddresses = shuffle(JSON.parse(JSON.stringify(conf.BOT_PAYMENT_ADDRESSES))).slice(0, conf.BOT_TRANSACTIONS_PER_MINUTE);

            getAvailableWallets(conf.BOT_TRANSACTIONS_PER_MINUTE, function(wallets) {
                var functions = [];

                if (paymentAddresses.length) {
                    var i = 0;

                    wallets.forEach(function(w) {
                        var toAddress = paymentAddresses[i % paymentAddresses.length];

                        functions.push(function(cb) {
                            var start_time = Date.now();
                            w.sendPayment(self.fee, toAddress, function(err, unit) {
                                cb(null, 'sendtoaddress '+JSON.stringify({ walletId: w.walletId, toAddress: toAddress })+' took '+(Date.now()-start_time)+'ms, unit='+unit+', err='+err);
                            });
                        });

                        i++;
                    });
                }

                async.series(functions, function(err, results) {
                    console.log('*******job finished*******');
                    console.log('errors', err);
                    console.log('results', results);
                    runJob();
                });
            });
        }, 1000 * conf.BOT_PAYMENT_INTERVAL);
    }

    function init() {
		initWallets(function() {
			runJob();
		});
    }

    return {
    	init: init
	};
}