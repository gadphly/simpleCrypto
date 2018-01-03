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

    typealias UInt8Ptr = UnsafeMutablePointer<UInt8>?

    public func generateRSAKey() -> Bool {
        
        // Init RSA key
        let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nil);
        
        if (EVP_PKEY_keygen_init(ctx) <= 0 ) {
            print("FAILURE at EVP_PKEY_keygen_init")
            return false
        }
        
        // EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH) is a complex macros and
        // therefore the compiler doesnt convert it directly to swift.
        // from /usr/local/opt/openssl/include/openssl/rsa.h
        // # define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)

        if (EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, RSA_KEY_LENGTH, nil) <= 0) {
            print("FAILURE at EVP_PKEY_CTX_set_rsa_keygen_bits")
            return false
        }
        
        // EVP_PKEY_CTX_set_rsa_padding is a complex macro. From rsa.h:
        // # define EVP_PKEY_CTX_set_rsa_padding(ctx, pad) EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL)
        
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, RSA_PKCS1_OAEP_PADDING, nil)

        
        if(EVP_PKEY_keygen(ctx, &myRSA.rsaKeypair) <= 0) {
            print("FAILURE at EVP_PKEY_keygen")
            return false
        }
        EVP_PKEY_CTX_free(ctx);
        return true
    }
    
    // Creates the AES key and IV
    public func evpRSAInit() -> Bool {
        
        // Initalize contexts
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size
        
        // rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
        myRSA.rsaEncryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        // set some of the options
        EVP_CIPHER_CTX_set_padding(myRSA.rsaEncryptCtx, RSA_PKCS1_OAEP_PADDING)
        
        EVP_CIPHER_CTX_init(myRSA.rsaEncryptCtx);
        EVP_CIPHER_CTX_init(myRSA.rsaDecryptCtx);
        
        return true
    }
    
    public func evpRSADeinit() {
        
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size
        
        myRSA.rsaEncryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myRSA.rsaDecryptCtx?.deallocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        if (myRSA.rsaKeypair != nil) {
            EVP_PKEY_free(myRSA.rsaKeypair)
        }

    }
    
    // Uses aes_256_cbc for envelope
    // Takes in a plaintext, then generates an AES key and IV for aes_256_cbc encryption of the plaintext
    // encrypts the key using the RSA key context has been initialized with.
    public func rsaEncrypt(plaintext: String) -> (  Data? ,  // ciphertext
                                                    Data? ,  // encKey
                                                    Data?) { // IV

        var processedLength: Int32 = 0
        var encLength: Int32 = 0
                                                        
        let pubKeyCount = 1   // using only 1 public key pair
        // All Seal*() return 0 on error or npubk if successful

        // unsigned char **ek
        // ek is an array of buffers where the public key encrypted secret key will be written,
        // each buffer must contain enough room for the corresponding encrypted key:
        // that is ek[i] must have room for EVP_PKEY_size(pubk[i]) bytes.
        // Here we are only using 1 public key, so ek[] has only 1 entry
        // In Swift, to do (unsigned char **ek), we have to do a little typealias'ing trick and
        // create a new pointer that point to the original pointer
        var ek: UInt8Ptr
        ek = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_PKEY_size(myRSA.rsaKeypair)))
        let ekPtr = UnsafeMutablePointer<UInt8Ptr>.allocate(capacity: MemoryLayout<UInt8Ptr>.size)
        ekPtr.pointee = ek
        
        // assign size of the corresponding cipher's IV
        let IVLength = EVP_CIPHER_iv_length(EVP_aes_256_cbc()) // EVP_MAX_IV_LENGTH
        let iv = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(IVLength))
        
        let enc = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + Int(IVLength))
        var encKeyLength: Int32 = 0

        // initializes a cipher context ctx for encryption with cipher type using a random secret key and IV.
        // The secret key is encrypted using the public key (can be a set of public keys)
        // Here we are using just 1 public key
        var status = EVP_SealInit(myRSA.rsaEncryptCtx, EVP_aes_256_cbc(), ekPtr, &encKeyLength, iv, &myRSA.rsaKeypair, 1)
        // SealInit should return the number of public keys that were input, here it is only 1
        guard status == pubKeyCount else {
            print("FAILURE at EVP_SealInit")
            return (nil, nil, nil)
        }

        //  int EVP_SealUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
        // EVP_SealUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        // # define EVP_SealUpdate(a,b,c,d,e)       EVP_EncryptUpdate(a,b,c,d,e)
        status = EVP_EncryptUpdate(myRSA.rsaEncryptCtx, enc, &processedLength, plaintext, Int32(plaintext.count))
        guard status == pubKeyCount else {
            print("FAILURE at EVP_SealInit")
            return (nil, nil, nil)
        }
        encLength = processedLength

        status = EVP_SealFinal(myRSA.rsaEncryptCtx, enc.advanced(by: Int(encLength)), &processedLength)
        guard status == pubKeyCount else {
            print("FAILURE at EVP_SealInit")
            return (nil, nil, nil)
        }
        encLength = encLength + processedLength

        EVP_CIPHER_CTX_cleanup(myRSA.rsaEncryptCtx);
        
        return ( Data(bytes: enc, count: Int(encLength)),
                 Data(bytes: ek!, count: Int(encKeyLength)),
                 Data(bytes: iv, count: Int(IVLength)) )
    }
    
    // returns decrypted message
    public func rsaDecryption(ciphertext: Data, encKey: Data, IV: Data ) -> Data? {
        
        // This is the number of bytes that each EVP_DecryptUpdate/EVP_DecryptFinal decrypts.
        // The sum of processedLen is the total size of the decrypted message (decMsgLen)
        var processedLen: Int32 = 0
        var decMsgLen: Int32 = 0
        
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(ciphertext.count + IV.count))
        decrypted.initialize(to: 0, count: Int(ciphertext.count + IV.count))
        
        // EVP_OpenInit returns 0 on error or a non zero integer (actually the recovered secret key size) if successful
        var status = encKey.withUnsafeBytes({ (ek: UnsafePointer<UInt8>) -> Int32 in
            return IV.withUnsafeBytes({ (iv: UnsafePointer<UInt8>) -> Int32 in
                return EVP_OpenInit(myRSA.rsaDecryptCtx, EVP_aes_256_cbc(), ek, Int32(encKey.count), iv, myRSA.rsaKeypair)
            })
        })

            
        guard status != EVP_CIPHER_key_length(EVP_aes_256_cbc()) else {
            print("FAILURE at EVP_OpenInit")
            return nil
        }

        // EVP_OpenUpdate is a complex macros and therefore the compiler doesnt
        // convert it directly to swift. From /usr/local/opt/openssl/include/openssl/evp.h:
        // # define EVP_OpenUpdate(a,b,c,d,e)       EVP_DecryptUpdate(a,b,c,d,e)
        status = ciphertext.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(myRSA.rsaDecryptCtx, decrypted, &processedLen, enc, Int32(ciphertext.count))
        })
        guard status != 0 else {
            print("FAILURE at EVP_DecryptUpdate")
            return nil
        }
        
        decMsgLen = processedLen;
        
        status = EVP_OpenFinal(myRSA.rsaDecryptCtx, decrypted.advanced(by: Int(decMsgLen)), &processedLen)
        guard status != 0 else {
            print("FAILURE at EVP_OpenFinal")
            return nil
        }
        decMsgLen = decMsgLen + processedLen
        
        EVP_CIPHER_CTX_cleanup(myRSA.rsaDecryptCtx);
        return Data(bytes: decrypted, count: Int(decMsgLen))
    }
    
    
    // generate rsa key before calling this function
    // returns a signature even though we are verifying the signature here anyway
    public func evpDigestSignVerifyVanilla(of message: String) -> Data? {
        
        print("Sign: \(message) ")
        
        // EVP_MD_CTX_create() renamed to _new
        let md_ctx = EVP_MD_CTX_create()
        let md_ctx_verify = EVP_MD_CTX_create()
        
        // OpenSSL_add_all_digests()
        // The digest table must be initialized using, for example, OpenSSL_add_all_digests() for these functions to work.
        // let md = EVP_get_digestbyname("SHA256")
        // check if md is not null. ALternative we can use functions like EVP_sha256()
        
        var rc = EVP_DigestSignInit(md_ctx, nil, EVP_sha256(), nil, myRSA.rsaKeypair)
        // check rc = 1

        // rc = EVP_DigestSignUpdate(md_ctx, message, message.count)
        // complex macro, so replace with what's in evp.h
        rc = EVP_DigestUpdate(md_ctx, message, message.count)
        // check rc = 1

        // Determine the size of the signature: there are 2 ways as shown below. The latter is the correct one to use.
        // This is the maximum bound on the size of the signature before the signature is created.
//        var sig_len: Int = Int(EVP_PKEY_size(myRSA.rsaKeypair))
//        let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)

        // Alternatively, we can use the following method to get the actual size of the signature that is generated (which could be smaller)
        var sig_len: Int = 0
        rc = EVP_DigestSignFinal(md_ctx, nil, &sig_len)
        // check rc = 1
//        print("lengths = \(sig_len), \(EVP_PKEY_size(myRSA.rsaKeypair)) ")
//        if (sig_len != EVP_PKEY_size(myRSA.rsaKeypair)) {
//            print("These two signature lengths should match! ")
//            return nil
//        }
        let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)

        
        rc = EVP_DigestSignFinal(md_ctx, sig, &sig_len)
        guard rc == 1 else {
            print("EVP_DigestSignFinal failure: \( ERR_get_error())")
            return nil
        }

        print("signature (\(sig_len)) = \(Data(bytes: sig, count: sig_len).hexEncodedString())")
        
        // Verify signature just produced
        rc = EVP_DigestVerifyInit(md_ctx_verify, nil, EVP_sha256(), nil, myRSA.rsaKeypair)
        // check rc = 1

        // rc = EVP_DigestVerifyUpdate(md_ctx_verify, message, message.count)
        // complex macro
        rc = EVP_DigestUpdate(md_ctx_verify, message, message.count)
        // check rc = 1

        // Unlike other return values, this return indicates if signature verifies or not
        rc = EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len)
        print("signature verified = \(rc == 1 ? "OK" : "FAIL")")
        
        EVP_MD_CTX_destroy(md_ctx)
        EVP_MD_CTX_destroy(md_ctx_verify)
        // EVP_PKEY_free(myRSA.rsaKeypair)

        return Data(bytes: sig, count: sig_len)
    }

    // This is for alternative signing operations such as different padding schemes
    public func evpDigestSignVerifyCustom(of message: String) -> Data? {
        
        print("Sign: \(message) ")
        
        // EVP_MD_CTX_create() renamed to EVP_MD_CTX_new()
        let md_ctx = EVP_MD_CTX_create()
        let md_ctx_verify = EVP_MD_CTX_create()
        
        // custom signing
        var pkey_ctx = EVP_PKEY_CTX_new(myRSA.rsaKeypair, nil)
        
        var rc = EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), nil, myRSA.rsaKeypair)
        // check rc = 1
        
        // Now that Init has initialized pkey_ctx, set the options we want
        //        EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING)
        //        complex macro need to be replaced
        EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, RSA_X931_PADDING, nil)
        //        EVP_PKEY_CTX_set_signature_md()

        
        rc = EVP_DigestUpdate(md_ctx, message, message.count)
        // check rc = 1
        
        // Determine the size of the actual signature
        var sig_len: Int = 0
        rc = EVP_DigestSignFinal(md_ctx, nil, &sig_len)
        // check rc = 1
        let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)
        
        rc = EVP_DigestSignFinal(md_ctx, sig, &sig_len)
        print("Signed = \(rc == 1 ? "OK" : "FAIL")")
        
        // pkey_ctx is "owned" by md_ctx. Just free md_ctx and pkey_ctx also gets freed
        EVP_MD_CTX_destroy(md_ctx)

        
//        print("signature (\(sig_len)) = \(Data(bytes: sig, count: sig_len).hexEncodedString())")
        
        
        // test validity of signature
        rc = EVP_DigestVerifyInit(md_ctx_verify, &pkey_ctx, EVP_sha256(),nil, myRSA.rsaKeypair)
        // check rc = 1
        
        // Now that Init has initialized pkey_ctx, set the padding options we want
        EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, RSA_X931_PADDING, nil)

        //        rc = EVP_DigestVerifyUpdate(md_ctx_verify, message, message.count)
        rc = EVP_DigestUpdate(md_ctx_verify, message, message.count)
        // check rc = 1

        // Unlike other return values, this return indicates if signature verifies or not
        rc = EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len)
        print("signature verified = \(rc == 1 ? "OK" : "FAIL")")
        
        // pkey_ctx is "owned" by md_ctx. Just free md_ctx and pkey_ctx also gets freed
        EVP_MD_CTX_destroy(md_ctx_verify)
        // EVP_PKEY_free(myRSA.rsaKeypair)

        return Data(bytes: sig, count: sig_len)
    }
}
