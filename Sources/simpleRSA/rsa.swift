//
//  rsa.swift
//  simpleRSAPackageDescription
//
//  Created by Gelareh Taban on 11/29/17.
//

import Foundation
import OpenSSL

class myRSA: NSObject {

    let RSA_KEY_LENGTH:Int32 = 2048;
    let PUB_EXP:UInt = 3;

    // Create an RSA key from both a hardcoded string as well as a file
    public func readRSAKey() throws {

        let pubKey: String = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTJzHdZaCCBXJojhEMTJ3yIVsw\nKpsdBIl/8InTkuL6NuCImSRJ3bvNZNOexepFybDrSHuKlAH3IFcY5VUamkSX+e0O\nxT5ho0TgBULr3vNj58oDT5ejFjYx2Zd8ZcpAqrVcKKJj2ueZajr1Azf+h8Pxhdf0\nuRVurAkltDfWqxKTGwIDAQAB\n-----END PUBLIC KEY-----"
        let path = URL(fileURLWithPath: #file).appendingPathComponent("../../../certs/private.pem").standardized
        print("path - \(path.path)")
        let priKey = try String(contentsOf: path, encoding: String.Encoding.ascii)

        let bio = BIO_new(BIO_s_mem())
        var rsa = RSA_new()
        defer {
            RSA_free(rsa);
            BIO_free_all(bio);
        }

        guard bio != nil, rsa != nil else {
            print("BIO_new, RSA_new failure: \( ERR_get_error())")
            return
        }
        // BIO_write(bio, (void*)key, strlen((const char*)key));
        // convert String to Data to UnsafeRawPointer
        var keyData = pubKey.data(using: String.Encoding.utf8)!
        var len: Int32 = 0
        print("public key = \(String(data: keyData, encoding: String.Encoding.ascii) ?? "NULL"))")
        
        _ = keyData.withUnsafeBytes { (k: UnsafePointer<UInt8>)  in
            len = BIO_write(bio, k, Int32(keyData.count))
            
            print("BIO len = \(len)")
        }
        guard len != 0 else {
            print("BIO_write failure: \( ERR_get_error())")
            return
        }

        // PEM_read_bio_PUBKEY
        // RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
        // If both cb and u are NULL then the default callback routine is used which will typically prompt for the passphrase on the current terminal with echoing turned off.
        let evp_key = PEM_read_bio_PUBKEY(bio, nil, nil, nil)
        rsa = EVP_PKEY_get1_RSA( evp_key)

        guard rsa != nil, evp_key != nil else  {
            print("EVP_PKEY_get1_RSA failure: \( ERR_get_error())")
            return
        }
        print("public rsa = \(String(describing: rsa)) ")
        
        // Private key
        keyData = priKey.data(using: String.Encoding.utf8)!
        print("private key = \(String(data: keyData, encoding: String.Encoding.ascii) ?? "NULL"))")
        
        _ = keyData.withUnsafeBytes { (k: UnsafePointer<UInt8>)  in
            let len = BIO_write(bio, k, Int32(keyData.count))
            print("BIO len = \(len)")
        }
        guard len != 0 else {
            print("BIO_write failure: \( ERR_get_error())")
            return
        }

        let evp_pri_key = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
        rsa = EVP_PKEY_get1_RSA( evp_pri_key )
        guard rsa != nil, evp_key != nil else  {
            print("EVP_PKEY_get1_RSA failure: \( ERR_get_error())")
            return
        }
        print("private rsa = \(String(describing: rsa)) ")
    }
    

    public func rsaEncDec() {

        // Generate key pair
        print("Generating RSA (\(RSA_KEY_LENGTH)) bits keypair...");
        
        // This function has become deprecated and we should be using RSA_generate_key_ex
        
        //RSA *keypair = RSA_generate_key(RSA_KEY_LENGTH, PUB_EXP, NULL, NULL);
        guard let keypair = RSA_generate_key(RSA_KEY_LENGTH, PUB_EXP, nil, nil) else {
            print("ABORT")
            abort()
        }
        
        // To get the C-string PEM form:
        guard let pri = BIO_new(BIO_s_mem()), let pub = BIO_new(BIO_s_mem()) else {
            abort()
        }
        defer {
            RSA_free(keypair);
            BIO_free_all(pub);
            BIO_free_all(pri);
        }
        
        PEM_write_bio_RSAPrivateKey(pri, keypair, nil, nil, 0, nil, nil);
        PEM_write_bio_RSAPublicKey(pub, keypair);
        
        // let pri_len = BIO_pending(pri);
        // BIO_pending is a complex macros and therefore the compiler doesnt
        // convert it directly to swift
        // in crypto/bio/bio.h
        // #define BIO_pending(b)      (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
        
        // BIO_read expects this to be Int32
        let pri_len = BIO_ctrl(pri, BIO_CTRL_PENDING, 0, nil)
        let pub_len = BIO_ctrl(pub, BIO_CTRL_PENDING, 0, nil)
        
        // BIO_read expects this to be UnsafeMutableRawPointer
        // pri_key = malloc(pri_len + 1);
        // pub_key = malloc(pub_len + 1);
        
        let CCHAR_LENGTH = MemoryLayout<CChar>.size
        let CCHAR_ALIGNMENT = MemoryLayout<CChar>.alignment
        
        // Add 1 extra character for null termination for the following variables
        let bytes = RSA_KEY_LENGTH / Int32(CCHAR_LENGTH) + 1
        let pri_key = UnsafeMutableRawPointer.allocate(bytes: pri_len + 1, alignedTo: CCHAR_ALIGNMENT)
        defer {
            pri_key.deallocate(bytes: pri_len + 1, alignedTo: CCHAR_ALIGNMENT)
        }
        
        let pub_key = UnsafeMutableRawPointer.allocate(bytes: pub_len + 1, alignedTo: CCHAR_ALIGNMENT)
        defer {
            pub_key.deallocate(bytes: pub_len + 1, alignedTo: CCHAR_ALIGNMENT)
        }
        
        
        BIO_read(pri, pri_key, Int32(pri_len));
        BIO_read(pub, pub_key, Int32(pub_len));
        
        // null terminate the string
        pri_key.advanced(by: pri_len).storeBytes(of: 0, as: CChar.self)
        pub_key.advanced(by: pub_len).storeBytes(of: 0, as: CChar.self)
        
        let pri_cchar = UnsafePointer(pri_key.bindMemory(to: CChar.self, capacity: Int(bytes)))
        let pub_cchar = UnsafePointer(pub_key.bindMemory(to: CChar.self, capacity: Int(bytes)))
        
        print(String(cString: pri_cchar))
        print(String(cString: pub_cchar))
        
        // alternatively...
        //let pri_buffer_ptr = UnsafeBufferPointer(start: pri_key.assumingMemoryBound(to: CChar.self), count: Int(bytes))
        //print(String(cString: pri_buffer_ptr.baseAddress!))
        
        // Get the message to encrypt
        // make sure it's less than 256 characters since we are using a 2048b key and we are not accounting for multiple blocks
        let plaintext = "To Encrypt or not to Encrypt"
        print("Plaintext (\(plaintext.utf8.count)): \(plaintext)");
        
        // expected type by RSA_public_encrypt  CUnsignedChar
        let encrypt = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(RSA_size(keypair)))
        defer {
            encrypt.deallocate(capacity: Int(RSA_size(keypair)))
        }
        
        let encrypt_len = RSA_public_encrypt(Int32(plaintext.utf8.count), plaintext, encrypt, keypair, RSA_PKCS1_OAEP_PADDING)
        
        if ( encrypt_len == -1 ) {
            // the error codes can be obtained by ERR_get_error.
            let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
            defer {
                err.deallocate(capacity: 130)
            }
            
            ERR_load_crypto_strings()
            ERR_error_string(ERR_get_error(), err)
            let err_str = String(utf8String: UnsafePointer(err))
            print("Encryption error: \(err_str ?? "NULL")")
        }
        
        // Print encrypted message
        let encrypted_str = String(cString: UnsafePointer(encrypt))
        print("Ciphertext (\(encrypt_len))= \(encrypted_str)")
        
        let decryption = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encrypt_len))
        defer {
            decryption.deallocate(capacity: Int(encrypt_len))
        }
        
        let decryption_length = RSA_private_decrypt(encrypt_len, encrypt, decryption, keypair, RSA_PKCS1_OAEP_PADDING)
        
        if ( decryption_length == -1 ) {
            // the error codes can be obtained by ERR_get_error.
            let err = UnsafeMutablePointer<CChar>.allocate(capacity: 130)
            defer {
                err.deallocate(capacity: 130)
            }
            ERR_load_crypto_strings()
            ERR_error_string(ERR_get_error(), err)
            let err_str = String(utf8String: UnsafePointer(err))
            print("Decryption error: \(err_str  ?? "NULL")")
        }
        
        // null terminate the ciphertext to be able to print it
        //let encryption =
        // Print encrypted message
        let decryption_str = String(cString: UnsafePointer(decryption))
        
        print("Decrypted ciphertext (\(decryption_length))= \(decryption_str)")

    }
}

