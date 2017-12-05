//
//  evp_rsa.swift
//  simpleRSAPackageDescription
//
//  Created by Gelareh Taban on 11/29/17.
//

import Foundation
import OpenSSL


extension myRSA {
    
    // EVP_PKEY = general private key without reference to any particular algorithm
    static var rsaKeypair: UnsafeMutablePointer<EVP_PKEY>? = nil

    static var rsaEncryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    static var rsaDecryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil

    typealias PtrToPtr = UnsafeMutablePointer<UInt8>?

    public func generateRSAKey() -> Bool {
        
        // Init RSA key
        let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
        
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
        
        if(EVP_PKEY_keygen(ctx, &myRSA.rsaKeypair) <= 0) {
            print("FAILURE at EVP_PKEY_keygen")
            return false
        }
        EVP_PKEY_CTX_free(ctx);
        return true
    }
    
    public func evpRSADeinit() {
        
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size

        myRSA.rsaEncryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
    }

    // Creates the AES key and IV
    public func evpRSAInit() -> Bool {
        
        // Initalize contexts
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size
        
        // rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
        myRSA.rsaEncryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        EVP_CIPHER_CTX_init(myRSA.rsaEncryptCtx);
        EVP_CIPHER_CTX_init(myRSA.rsaDecryptCtx);
        
        return true
    }
    
    
    //        rsaEncrypt(unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl) {
    public func rsaEncrypt(plaintext: String,
                           ciphertext: inout UnsafeMutablePointer<UInt8>? ,
                           cipherLength: inout Int32,
                           encKey: inout UnsafeMutablePointer<UInt8>? ,
                           encKeyLength: inout Int32,
                           IV: inout UnsafeMutablePointer<UInt8>? ,
                           IVLength: inout Int32 ) -> Bool {
        
        var encLength: Int32 = 0
        var ek: PtrToPtr
        ek = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_PKEY_size(myRSA.rsaKeypair)))
        
        // we need to create an array of pointers with ek
        let ekPtr = UnsafeMutablePointer<PtrToPtr>.allocate(capacity: MemoryLayout<PtrToPtr>.size)
        ekPtr.pointee = ek

//        IVLength = EVP_CIPHER_CTX_iv_length(myRSA.rsaEncryptCtx) // EVP_MAX_IV_LENGTH
        IVLength = EVP_MAX_IV_LENGTH
        let iv = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(IVLength))
        
        let enc = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + Int(IVLength))

        // initializes a cipher context ctx for encryption with cipher type using a random secret key and IV.
        // The secret key is encrypted using the public key (can be a set of public keys)
        // ek size = EVP_PKEY_size(pubk[i]) bytes
        // iv must contain enough room for the corresponding cipher's IV, as determined by (for example) EVP_CIPHER_iv_length(type).
        var status = EVP_SealInit(myRSA.rsaEncryptCtx, EVP_aes_256_cbc(), ekPtr, &encKeyLength, iv, &myRSA.rsaKeypair, 1)
        guard status != 0 else {
            print("FAILURE at EVP_SealInit")
            return false
        }

        //  int EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
        // We really want to use EVP_SealUpdate but symbols don't resolve. So based on evp.h:
        // # define EVP_SealUpdate(a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)
        status = EVP_EncryptUpdate(myRSA.rsaEncryptCtx, enc, &encLength, plaintext, Int32(plaintext.count))
        guard status != 0 else {
            print("FAILURE at EVP_SealInit")
            return false
        }
        cipherLength = encLength

        status = EVP_SealFinal(myRSA.rsaEncryptCtx, enc.advanced(by: Int(cipherLength)), &encLength)
        guard status != 0 else {
            print("FAILURE at EVP_SealInit")
            return false
        }
        cipherLength = cipherLength + encLength
        
        // assign values to be returned
        ciphertext = enc
        IV = iv
        encKey = ek

        let encrypted_str = String(cString: UnsafePointer(enc))
        print("Ciphertext (\(cipherLength))= \(encrypted_str)")

        EVP_CIPHER_CTX_cleanup(myRSA.rsaEncryptCtx);
        
        return true
    }
    
    //        int Crypto::rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl,
    //        unsigned char *iv, size_t ivl, unsigned char **decMsg) {
    public func rsaDecryption(ciphertext: UnsafeMutablePointer<UInt8> ,
                              cipherLength: Int32,
                              encKey: UnsafeMutablePointer<UInt8> ,
                              encKeyLength: Int32,
                              IV: UnsafeMutablePointer<UInt8> ,
                              IVLength: Int32,
                              decMsg: inout UnsafeMutablePointer<UInt8>? ,
                              decMsgLen: inout Int32) -> Bool {
        
        var decLen: Int32 = 0
        var processedLen: Int32 = 0
        
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(cipherLength + IVLength))
        
        let key = myRSA.rsaKeypair
        
        var status = EVP_OpenInit(myRSA.rsaDecryptCtx, EVP_aes_256_cbc(), encKey, encKeyLength, IV, key)
        guard status != 0 else {
            print("FAILURE at EVP_OpenInit")
            return false
        }

        // We really want to use EVP_OpenUpdate but symbols don't resolve. So based on evp.h:
        // # define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
        status = EVP_DecryptUpdate(myRSA.rsaDecryptCtx, decrypted, &processedLen, ciphertext, cipherLength)
        guard status != 0 else {
            print("FAILURE at EVP_DecryptUpdate")
            return false
        }
        
        decLen = processedLen;
        
        status = EVP_OpenFinal(myRSA.rsaDecryptCtx, decrypted.advanced(by: Int(decLen)), &processedLen)
        guard status != 0 else {
            print("FAILURE at EVP_OpenFinal")
            return false
        }
        decLen = decLen + processedLen

        let encrypted_str = String(cString: UnsafePointer(decrypted))
        print("DECRYPTED (\(decLen))= \(encrypted_str)")

        EVP_CIPHER_CTX_cleanup(myRSA.rsaDecryptCtx);
        return true
    }
    
}
