/*jslint node: true */
"use strict";
var db = require('core/db.js');
var ecdsaSig = require('core/signature.js');
var Mnemonic = require('bitcore-mnemonic');
var Bitcore = require('bitcore-lib');

function BotWallet() {
	var self = this;

    self.account = null;
    self.walletName = null;
    self.xPrivKey = null;
    self.walletId = null;

    function createWallet(onDone){
        var strXPubKey = Bitcore.HDPublicKey(self.xPrivKey.derive("m/44'/0'/"+ self.account + "'")).toString();
        var walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
        walletDefinedByKeys.createWalletByDevices(strXPubKey, self.account, 1, [], self.walletName, false, function(walletId){
            walletDefinedByKeys.issueNextAddress(walletId, 0, function() {
                onDone(walletId);
            });
        });
    }

    function signWithLocalPrivateKey(walletId, account, is_change, address_index, text_to_sign, handleSig){
        var path = "m/44'/0'/" + account + "'/"+is_change+"/"+address_index;
        var privateKey = self.xPrivKey.derive(path).privateKey;
        var privateKeyBuf = privateKey.bn.toBuffer({size:32});
        handleSig(ecdsaSig.sign(text_to_sign, privateKeyBuf));
    }

    function readLastAddress(handleAddress){
        db.query("SELECT address FROM my_addresses WHERE wallet=? AND is_change=0 ORDER BY address_index DESC", [self.walletId], function(rows){
            if (rows.length === 0)
                throw Error("no addresses");
            handleAddress(rows[0].address);
        });
    }

    self.isStableAndHasAmount = function(amount, callback) {
        console.log("*************************is-stable-and-has-amount - started*************************");
        console.log("*************************wallet*************************");
        console.log(self.walletId);

        var paymentFee = 1000;

        readLastAddress(function(address) {
            console.log("*************************address*************************");
            console.log(address);

            db.query("SELECT asset, is_stable, SUM(amount) AS balance \n\
                     FROM outputs JOIN units USING(unit) \n\
                     WHERE is_spent=0 AND address=? AND sequence='good' AND asset is NULL \n\
                     GROUP BY is_stable", [address],
                function(rows) {
                    var balance = {
                        isStable: true,
                        stable: 0,
                        pending: 0
                    };

                    for (var i = 0; i < rows.length; i++) {
                        var row = rows[i];
                        balance[row.is_stable ? 'stable' : 'pending'] = row.balance;
                        balance.isStable = balance.isStable && !!row.is_stable;
                    }

                    var result = balance.isStable && balance.stable >= (amount + paymentFee);

                    console.log("*************************info*************************");
                    console.log("balance", balance);
                    console.log("*************************is-stable-and-has-amount - finished*************************");

                    callback(result);
                });
        });
    };

    self.sendPayment = function(amount, toAddress, onDone){
        console.log("*************************send-payment - started*************************");
        console.log("*************************wallet*************************");
        console.log(self.walletId);

        console.log("amount", amount);
        console.log("to-address", toAddress);

        var walletDefinedByKeys = require('core/wallet_defined_by_keys.js');

        walletDefinedByKeys.issueNextAddress(self.walletId, 0, function(addressInfo) {
            var Wallet = require('core/wallet.js');
            Wallet.sendPaymentFromWallet(
                'base',
                self.walletId,
                toAddress,
                amount,
                addressInfo.address, //changeAddress
                [],
                null, //receiverDeviceAddress
                signWithLocalPrivateKey,
                function(err, unit, assocMnemonics){
                    console.log("error: ", err);
                    console.log("unit: ", unit);
                    console.log("*************************send-payment - finished*************************");

                    onDone(err, unit, assocMnemonics);
                }
            );
        });
    };

    self.composeAndSend = function(amount, toAddress, onDone) {
        var opts = {
            shared_address: null,
            asset: 'base',
            to_address: toAddress,
            amount: amount,
            send_all: false,
            arrSigningDeviceAddresses: [],
            recipientDeviceAddress: null,
            signWithLocalPrivateKey: signWithLocalPrivateKey,
            wallet: self.walletId
        };

        console.log("opts", opts);

        var walletDefinedByKeys = require('core/wallet_defined_by_keys.js');

        walletDefinedByKeys.issueNextAddress(self.walletId, 0, function(addressInfo) {
            opts.change_address = addressInfo.address;

            const Wallet = require('core/wallet.js');

            // create a new change address or select first unused one
            walletDefinedByKeys.issueOrSelectNextChangeAddress(self.walletId, function(objAddr) {
                opts.change_address = objAddr.address;

                Wallet.sendMultiPayment(opts, function (sendMultiPaymentError, unit, assocMnemonics) {
                    console.log("error: ", sendMultiPaymentError);
                    console.log("unit: ", unit);
                    console.log("*************************send-payment - finished*************************");

                    onDone(sendMultiPaymentError, unit, assocMnemonics);
                });
            });
        });
    };

    self.init = function(mnemonicPhrase, passphrase, account, cb) {
        self.account = account;
        self.walletName = "Bot Wallet " + self.account;

        var mnemonic = new Mnemonic(mnemonicPhrase);
        self.xPrivKey = mnemonic.toHDPrivateKey(passphrase);

        db.query("SELECT wallet FROM wallets WHERE account = ?", [self.account], function(rows){
            if (rows.length === 0) {
                createWallet(function (wId) {
                    self.walletId = wId;
                    cb();
                });
            } else {
                self.walletId = rows[0].wallet;
                cb();
            }
        });
    };

    return self;
}

exports.BotWallet = BotWallet;