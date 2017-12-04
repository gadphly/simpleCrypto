//
//  evp_rsa.swift
//  simpleRSAPackageDescription
//
//  Created by Gelareh Taban on 11/29/17.
//

import Foundation
import OpenSSL

extension myRSA {
    
    static let AES_KEYLEN_Bytes = 16 //256 bits
    
    // EVP_PKEY = general private key without reference to any particular algorithm
    static var localKeypair: UnsafeMutablePointer<EVP_PKEY>? = nil


    // unsigned char *aesKey, *aesIV
    static var aesKey: UnsafeMutablePointer<CUnsignedChar>? = nil
    static var aesIV: UnsafeMutablePointer<CUnsignedChar>? = nil

    static var rsaEncryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    static var aesEncryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    static var rsaDecryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    static var aesDecryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil

    public func evpRSADeInit() {
        
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size

        myRSA.rsaEncryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.aesEncryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.aesDecryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        let AES_KEY_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size

        myRSA.aesKey?.deallocate(capacity: AES_KEY_LENGTH)
        myRSA.aesIV?.deallocate(capacity: AES_KEY_LENGTH)

    }

    // Creates the AES key and IV
    public func evpRSAInit() -> Bool {
        
        // Initalize contexts
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size
        
        // rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
        myRSA.rsaEncryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.aesEncryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.aesDecryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        EVP_CIPHER_CTX_init(myRSA.rsaEncryptCtx);
        EVP_CIPHER_CTX_init(myRSA.aesEncryptCtx);

        EVP_CIPHER_CTX_init(myRSA.rsaDecryptCtx);
        EVP_CIPHER_CTX_init(myRSA.aesDecryptCtx);

        // Init RSA key
        var ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);

        if (EVP_PKEY_keygen_init(ctx) <= 0 ) {
            print("FAILURE at EVP_PKEY_keygen_init")
            return false
        }

        // We really want to use EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH) but
        // symbol isn't found so we are going to use what it defines
        if (EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, RSA_KEY_LENGTH, nil) <= 0) {
            print("FAILURE at EVP_PKEY_CTX_set_rsa_keygen_bits")
            return false
        }
        

        if(EVP_PKEY_keygen(ctx, &myRSA.localKeypair) <= 0) {
            print("FAILURE at EVP_PKEY_keygen")
            return false
        }
        EVP_PKEY_CTX_free(ctx);

        // Init AES
        myRSA.aesKey = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myRSA.AES_KEYLEN_Bytes)
        myRSA.aesIV = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myRSA.AES_KEYLEN_Bytes)
        
        let aesPass = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myRSA.AES_KEYLEN_Bytes)
        
        // we use salt if we want to use PBKDF for AES key generation
//        let aesSalt = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: 8)

        defer {
            aesPass.deallocate(capacity: myRSA.AES_KEYLEN_Bytes)
//            aesSalt.deallocate(capacity: 8)
        }
        
        // AES key generation - just do random
        
        // For the AES key we have the option of using a PBKDF (password-baswed key derivation formula)
        // or just using straight random data for the key and IV. Depending on your use case, you will
        // want to pick one or another.
//        #ifdef USE_PBKDF
//        // Get some random data to use as the AES pass and salt
//        if(RAND_bytes(aesPass, AES_KEYLEN/8) == 0) {
//            return FAILURE;
//        }
//
//        if(RAND_bytes(aesSalt, 8) == 0) {
//            return FAILURE;
//        }
//
//        if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, AES_KEYLEN/8, AES_ROUNDS, aesKey, aesIV) == 0) {
//            return FAILURE;
//}
//#else

        if(RAND_bytes(myRSA.aesKey, Int32(myRSA.AES_KEYLEN_Bytes)) == 0) {
            print("FAILURE at RAND_bytes for aesKey")
            return false
        }
        
        if(RAND_bytes(myRSA.aesIV, Int32(myRSA.AES_KEYLEN_Bytes)) == 0) {
            print("FAILURE at RAND_bytes for aesIV")
            return false
        }

//#endif // USE_PBKDF

        return true
    }
    
    //        int Crypto::aesEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg)
    public func evpAESEncrypt(plaintext: String,
                              ciphertext: inout UnsafeMutablePointer<UInt8>? ,
                              cipherLength: inout Int32) -> Bool {

        // set up cipher context for encryption with cipher type EVP_aes_256_cbc()
        // return 1 for success and 0 for failure.
        var status = EVP_EncryptInit_ex(myRSA.aesEncryptCtx, EVP_aes_256_cbc(), nil, myRSA.aesKey, myRSA.aesIV)
        if(status == 0) {
            print("FAILURE at EVP_EncryptInit_ex")
            return false
        }
        
        print("Plaintext (\(plaintext.utf8.count)): \(plaintext)");
        
        var encLength: Int32 = 0
        let enc = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + myRSA.AES_KEYLEN_Bytes - 1)

        // ciphertext = out, outl where outl = [0 ... (inl + cipher_block_size - 1) ]
        // return 1 for success and 0 for failure.
        status = EVP_EncryptUpdate(myRSA.aesEncryptCtx, enc, &encLength, plaintext, Int32(plaintext.count))
        
        print(EVP_CIPHER_block_size(EVP_aes_256_cbc()))
        
        var encrypted_str = String(cString: UnsafePointer(enc))
        print("Ciphertext (\(encLength))= \(encrypted_str)")

        cipherLength = cipherLength + encLength;

        // encrypts the "final" data, that is any data that remains in a partial block.
        status = EVP_EncryptFinal_ex(myRSA.aesEncryptCtx, enc.advanced(by: Int(cipherLength)), &encLength)
        if(status == 0) {
            print("FAILURE at EVP_EncryptInit_ex")
            return false
        }
        cipherLength = cipherLength + encLength;

        encrypted_str = String(cString: UnsafePointer(enc))
        print("Ciphertext (\(cipherLength))= \(encrypted_str)")

        ciphertext = enc
        EVP_CIPHER_CTX_cleanup(myRSA.aesEncryptCtx);
        
        return true
    }
    
    public func evpAESDecrypt(ciphertext: UnsafeMutablePointer<UInt8> ,
                              cipherLength: Int32,
                              decMsg: inout UnsafeMutablePointer<UInt8>? ,
                              decMsgLen: inout Int32) -> UInt32 {

        var decLen: Int32 = 0
        var processedLen: Int32 = 0

        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(cipherLength))

        var status = EVP_DecryptInit_ex(myRSA.aesDecryptCtx, EVP_aes_256_cbc(), nil, myRSA.aesKey, myRSA.aesIV)
        if (status == 0) {
            print("FAILURE at EVP_DecryptInit_ex")
            return 0
        }
        
        status = EVP_DecryptUpdate(myRSA.aesDecryptCtx, decrypted, &processedLen, ciphertext, cipherLength)
        if (status == 0) {
            print("FAILURE at EVP_DecryptUpdate")
            return 0
        }
        decLen = decLen + processedLen
        
        status = EVP_DecryptFinal_ex(myRSA.aesDecryptCtx, decrypted.advanced(by: Int(decLen)), &processedLen)
        if (status == 0) {
            print("FAILURE at EVP_DecryptFinal_ex")
            return 0
        }
        decLen = decLen + processedLen

        EVP_CIPHER_CTX_cleanup(myRSA.aesDecryptCtx);
        
        let encrypted_str = String(cString: UnsafePointer(decrypted))
        print("DECRYPTED (\(decLen))= \(encrypted_str)")

        return 1
    }
    
    //        rsaEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl) {
    public func rsaEncrypt() -> Bool {
        
//            size_t encMsgLen = 0;
//            size_t blockLen  = 0;
//
//            *ek = (unsigned char*)malloc(EVP_PKEY_size(remotePubKey));
//            *iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
//            if(*ek == NULL || *iv == NULL) return FAILURE;
//            *ivl = EVP_MAX_IV_LENGTH;
//
//            *encMsg = (unsigned char*)malloc(msgLen + EVP_MAX_IV_LENGTH);
//            if(encMsg == NULL) return FAILURE;
//
//            if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int*)ekl, *iv, &remotePubKey, 1)) {
//                return FAILURE;
//            }
//
//            if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)msg, (int)msgLen)) {
//                return FAILURE;
//            }
//            encMsgLen += blockLen;
//
//            if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
//                return FAILURE;
//            }
//            encMsgLen += blockLen;
//
//            EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
//
//            return (int)encMsgLen;
//        }
        
        return true
    }
}
