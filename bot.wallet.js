/*jslint node: true */
"use strict";
var db = require('core/db.js');
var ecdsaSig = require('core/signature.js');
var Mnemonic = require('bitcore-mnemonic');
var Bitcore = require('bitcore-lib');

function BotWallet() {
	var self = this;

    self.number = null;
    self.walletName = null;
    self.xPrivKey = null;
    self.walletId = null;

    function createWallet(onDone){
        var strXPubKey = Bitcore.HDPublicKey(self.xPrivKey.derive("m/44'/0'/"+ self.number + "'")).toString();
        var walletDefinedByKeys = require('core/wallet_defined_by_keys.js');
        walletDefinedByKeys.createWalletByDevices(strXPubKey, self.number, 1, [], self.walletName, false, function(walletId){
            walletDefinedByKeys.issueNextAddress(walletId, 0, function(){
                db.query("INSERT INTO bot_wallets (wallet, number) VALUES (?, ?)", [walletId, self.number], function() {
                    onDone(walletId);
                });
            });
        });
    }

    function signWithLocalPrivateKey(walletId, account, is_change, address_index, text_to_sign, handleSig){
        var path = "m/44'/0'/" + account + "'/"+is_change+"/"+address_index;
        var privateKey = self.xPrivKey.derive(path).privateKey;
        var privateKeyBuf = privateKey.bn.toBuffer({size:32});
        handleSig(ecdsaSig.sign(text_to_sign, privateKeyBuf));
    }

    function readFirstAddress(handleAddress){
        db.query("SELECT address FROM my_addresses WHERE wallet=? AND address_index=0 AND is_change=0", [self.walletId], function(rows){
            if (rows.length === 0)
                throw Error("no addresses");
            if (rows.length > 1)
                throw Error("more than 1 address");
            handleAddress(rows[0].address);
        });
    }

    self.isStableAndHasAmount = function(amount, callback) {
        console.log("*************************is-stable-and-has-amount - started*************************");
        console.log("*************************wallet*************************");
        console.log(self.walletId);

        var paymentFee = 2000;

        readFirstAddress(function(address) {
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

                    console.log("*************************result*************************");
                    console.log(result);
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

    self.init = function(mnemonicPhrase, passphrase, number, cb) {
        self.number = number;
        self.walletName = "Bot Wallet " + self.number;

        var mnemonic = new Mnemonic(mnemonicPhrase);
        self.xPrivKey = mnemonic.toHDPrivateKey(passphrase);

        db.query("SELECT wallet FROM bot_wallets WHERE number = ?", [self.number], function(rows){
            if (rows.length === 0) {
                createWallet(function (wId) {
                    self.walletId = wId;
                    cb(self);
                });
            } else {
                self.walletId = rows[0].wallet;
                cb(self);
            }
        });
    };

    return self;
}

exports.BotWallet = BotWallet;