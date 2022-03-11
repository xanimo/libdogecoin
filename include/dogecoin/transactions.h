// int startTX(); 
//     // #returns  an index of a transaction to build in memory.  (1, 2, etc) ..      

// int addUtxo(int txindex-from-startrawtx, char* HEX_UTXO_TXID, int VOUT, uint64_t dogecoinamount)
//     // #returns 1 if success.
    
// char* createTx(int txindex, char* destinationaddress, float subtractedfee, uint64_t* out_dogeamount_for_verification);   
//     // #'closes the inputs', specifies the recipient, specifies the amnt-to-subtract-as-fee, and returns the raw tx..
//     // # out_dogeamount == just an echoback of the total amount specified in the addutxos for verification

// char* getRawTx(int txindex);
//     // #returns 0 if not closed, returns rawtx again if closed/created.

// int clearTx(int txindex); 
//     // #clears a tx in memory. (overwrites)

// char* signIndexedTx(int txindex, char* privkey);
//     // #signs transaction "txindex" with key "privkey" and returns hex signed transaction.

// char* signRawTx(char* incomingrawtx, char* privkey);
//     // #sign a given inputted transaction with a given private key, and return a hex signed transaction.

// //may want to add such things to 'advanced' section:
// //locktime, possibilities for multiple outputs, data, sequence.