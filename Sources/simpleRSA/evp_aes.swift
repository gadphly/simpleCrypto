//
//  evp_aes.swift
//
//  Created by Gelareh Taban on 12/4/17.
//

import Foundation
import OpenSSL

class myAES: NSObject {
        
    // unsigned char *aesKey, *aesIV
    static var aesKey: UnsafeMutablePointer<CUnsignedChar>? = nil
    static var aesIV: UnsafeMutablePointer<CUnsignedChar>? = nil
    static var aesKeyLen: Int = 0

    static var aesEncryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    static var aesDecryptCtx: UnsafeMutablePointer<EVP_CIPHER_CTX>? = nil
    
    override init() {
        
        // Initalize contexts
        let EVP_CIPHER_CTX_LENGTH = MemoryLayout<EVP_CIPHER_CTX>.size
        
        // rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
        myAES.aesEncryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        myAES.aesDecryptCtx = UnsafeMutablePointer<EVP_CIPHER_CTX>.allocate(capacity: EVP_CIPHER_CTX_LENGTH)
        
        EVP_CIPHER_CTX_init(myAES.aesEncryptCtx);
        EVP_CIPHER_CTX_init(myAES.aesDecryptCtx);
        
        super.init()
    }
    
    deinit {
        myAES.aesEncryptCtx?.deallocate(capacity: MemoryLayout<EVP_CIPHER_CTX>.size)
        myAES.aesDecryptCtx?.deallocate(capacity: MemoryLayout<EVP_CIPHER_CTX>.size)
        
        myAES.aesKey?.deallocate(capacity: MemoryLayout<EVP_CIPHER_CTX>.size)
        myAES.aesIV?.deallocate(capacity: MemoryLayout<EVP_CIPHER_CTX>.size)
    }

    
    // size is number of bytes
    //
    // TODO: add type for PBKDF or Randm
    public func generateAESKey(of keyLen: Int) -> Bool {
        
        myAES.aesKeyLen = keyLen
        
        // Init AES
        myAES.aesKey = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myAES.aesKeyLen)
        myAES.aesIV = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myAES.aesKeyLen)
        
        // AES key generation - just do random
        
        // For the AES key we have the option of using a PBKDF (password-baswed key derivation formula)
        // or just using straight random data for the key and IV. Depending on your use case, you will
        // want to pick one or another.
        
        //  #ifdef USE_PBKDF
        //
        //        we use salt if we want to use PBKDF for AES key generation
        //        let aesPass = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: myAES.aesKeyLen)
        //        let aesSalt = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: 8)
        //        defer {
        //            aesPass.deallocate(capacity: myAES.aesKeyLen)
        //            aesSalt.deallocate(capacity: 8)
        //        }

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
        //  #else
        
        if(RAND_bytes(myAES.aesKey, Int32(myAES.aesKeyLen)) == 0) {
            print("FAILURE at RAND_bytes for aesKey")
            return false
        }
        
        if(RAND_bytes(myAES.aesIV, Int32(myAES.aesKeyLen)) == 0) {
            print("FAILURE at RAND_bytes for aesIV")
            return false
        }
        //#endif // USE_PBKDF

        return true
    }
    
    
    //        int Crypto::aesEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg)
    //
    public func evpAESEncrypt(plaintext: String) -> Data? {

        // set up cipher context for encryption with cipher type EVP_aes_256_cbc()
        // return 1 for success and 0 for failure.
        var status = EVP_EncryptInit_ex(myAES.aesEncryptCtx, EVP_aes_256_cbc(), nil, myAES.aesKey, myAES.aesIV)
        if(status == 0) {
            print("FAILURE at EVP_EncryptInit_ex")
            return nil
        }
        
        var encLength: Int32 = 0
        var processedLength = encLength
        let enc = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintext.count + myAES.aesKeyLen - 1)
        
        // ciphertext = out, outl where outl = [0 ... (inl + cipher_block_size - 1) ]
        // return 1 for success and 0 for failure.
        status = EVP_EncryptUpdate(myAES.aesEncryptCtx, enc, &processedLength, plaintext, Int32(plaintext.count))
        encLength = processedLength
        
        // encrypts the "final" data, that is any data that remains in a partial block.
        status = EVP_EncryptFinal_ex(myAES.aesEncryptCtx, enc.advanced(by: Int(encLength)), &processedLength)
        if(status == 0) {
            print("FAILURE at EVP_EncryptInit_ex")
            return nil
        }
        encLength = encLength + processedLength

        EVP_CIPHER_CTX_cleanup(myAES.aesEncryptCtx);
        
        return Data(bytes: enc, count: Int(encLength))
    }
    
    // returns decrypted message
    public func evpAESDecrypt(ciphertext: Data) -> Data? {
    
        var decMsgLength: Int32 = 0
        var processedLen: Int32 = 0
        
        let decrypted = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(ciphertext.count))
        
        var status = EVP_DecryptInit_ex(myAES.aesDecryptCtx, EVP_aes_256_cbc(), nil, myAES.aesKey, myAES.aesIV)
        if (status == 0) {
            print("FAILURE at EVP_DecryptInit_ex")
            return nil
        }
        
        status = ciphertext.withUnsafeBytes({ (enc: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DecryptUpdate(myAES.aesDecryptCtx, decrypted, &processedLen, enc, Int32(ciphertext.count))
        })
        
        if (status == 0) {
            print("FAILURE at EVP_DecryptUpdate")
            return nil
        }
        decMsgLength = processedLen
        
        status = EVP_DecryptFinal_ex(myAES.aesDecryptCtx, decrypted.advanced(by: Int(decMsgLength)), &processedLen)
        if (status == 0) {
            print("FAILURE at EVP_DecryptFinal_ex")
            return nil
        }
        decMsgLength = decMsgLength + processedLen
        
        EVP_CIPHER_CTX_cleanup(myAES.aesDecryptCtx);
        
        return Data(bytes: decrypted, count: Int(decMsgLength))
    }
    
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
