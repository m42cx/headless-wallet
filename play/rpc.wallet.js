/*jslint node: true */
"use strict";
var db = require('core/db.js');
var ecdsaSig = require('core/signature.js');
var Mnemonic = require('bitcore-mnemonic');
var Bitcore = require('bitcore-lib');

function RpcWallet() {
	var self = this;

  self.account = null;
  self.walletName = null;
  self.xPrivKey = null;
  self.walletId = null;
  self.walletAddress = null;

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
  
  function getLatestAccountNumber(handleAccountNumber) {
   db.query("SELECT MAX(account) AS account FROM wallets", function(rows){
      if (rows.length === 0)
        throw Error("no account");
      handleAccountNumber(rows[0].account);
    });
  }

  self.createNewWallet = function(mnemonicPhrase, passphrase, account, cb) {   
    getLatestAccountNumber(function (accountNumber){
      self.account = accountNumber + 1;
      self.walletName = "headless wallet " + self.account;

      var mnemonic = new Mnemonic(mnemonicPhrase);
      self.xPrivKey = mnemonic.toHDPrivateKey(passphrase);

      createWallet(function (wId) {
        self.walletId = wId;
        readLastAddress(function (address) {
          self.walletAddress = address;
          cb();
        });
      });
    });
  };

  return self;
}

exports.RpcWallet = RpcWallet;