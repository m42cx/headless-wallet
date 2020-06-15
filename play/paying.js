/*jslint node: true */
"use strict";
const fs = require('fs');
const headlessWallet = require('../start.js');
const eventBus = require('core/event_bus.js');
let paying_address;
let payee_address;

function onError(err){
	throw Error(err);
}

        paying_address = "KZWAFFUQSUAK3ZIMZFE5F5GV2WVCII6P";
	payee_address = "6XJR3H7ZX32CAVWXVSD2T52QUR63QWPE";

function createPayment() {
	let composer = require('core/composer.js');
	let network = require('core/network.js');
	let callbacks = composer.getSavingCallbacks({
		ifNotEnoughFunds: onError,
		ifError: onError,
		ifOk: function(objJoint){
			network.broadcastJoint(objJoint);
		}
	});

	let arrOutputs = [
		{address: paying_address, amount: 0},      // the change
		{address: payee_address, amount: 100}  // the receiver
	];
	console.log('>>', paying_address);
	composer.composePaymentJoint([paying_address], arrOutputs, headlessWallet.signer, callbacks);
 // process.exit();
}

 eventBus.on('headless_wallet_ready', function() {
	console.log(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Create payment");
	setInterval(createPayment, 4000);
});

