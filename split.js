/* jslint node: true */

'use strict';

const db = require('byteballcore/db.js');

const COUNT_CHUNKS = 10;

// finds the largest output on this address and splits it in 10 chunks
function splitLargestOutput(address) {
    function onError(err) {
        console.log(`failed to split: ${err}`);
    }
    const network = require('byteballcore/network.js');
    const composer = require('byteballcore/composer.js');
    const headlessWallet = require('./start.js');
    console.log(`will split the largest output on ${address}`);
    createSplitOutputs(address, (arrOutputs) => {
        if (!arrOutputs) { return; }
        composer.composeAndSavePaymentJoint([address], arrOutputs, headlessWallet.signer, {
            ifNotEnoughFunds: onError,
            ifError: onError,
            ifOk(objJoint) {
                network.broadcastJoint(objJoint);
            }
        });
    });
}

function createSplitOutputs(address, handleOutputs) {
    db.query('SELECT amount FROM outputs WHERE address=? AND asset IS NULL AND is_spent=0 ORDER BY amount DESC LIMIT 1', [address], (rows) => {
        if (rows.length === 0) { return handleOutputs(); }
        const amount = rows[0].amount;
        const chunk_amount = Math.round(amount / COUNT_CHUNKS);
        const arrOutputs = [{ amount: 0, address }];
        for (let i = 1; i < COUNT_CHUNKS; i++) // 9 iterations
            { arrOutputs.push({ amount: chunk_amount, address }); }
        handleOutputs(arrOutputs);
    });
}

// splits the largest output if it is greater than the 1/10th of the total
function checkAndSplitLargestOutput(address) {
    db.query( // see if the largest output is greater than the 1/10th of the total
        'SELECT COUNT(*) AS count FROM outputs \n\
        WHERE address=? AND is_spent=0 AND asset IS NULL \n\
            AND amount>(SELECT SUM(amount)+10000 FROM outputs WHERE address=? AND is_spent=0 AND asset IS NULL)/(?/2)',
        [address, address, COUNT_CHUNKS],
        (rows) => {
            if (rows[0].count > 0) { splitLargestOutput(address); }
        }
    );
}

// periodically checks and splits if the largest output becomes too large compared with the total
function startCheckingAndSplittingLargestOutput(address, period) {
    checkAndSplitLargestOutput(address);
    setInterval(() => {
        checkAndSplitLargestOutput(address);
    }, period || 600 * 1000);
}

exports.splitLargestOutput = splitLargestOutput;
exports.checkAndSplitLargestOutput = checkAndSplitLargestOutput;
exports.startCheckingAndSplittingLargestOutput = startCheckingAndSplittingLargestOutput;

