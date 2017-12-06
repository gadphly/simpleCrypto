import Foundation
import OpenSSL

func main() {

    let plaintext = "In those days spirits were brave, the stakes were high, men were real men, women were real women and small furry creatures from Alpha Centauri were real small furry creatures from Alpha Centauri."
    
    print(plaintext)
    testAESEnv(with: plaintext)
    testRSAEnv(with: plaintext)

}

func testAESEnv(with plaintext: String) {
    
    let AES_KEYLEN_Bytes = 16 //256 bits
    let u = myAES()

    // AES ciphertext has range [0 ... (inl + cipher_block_size - 1) ]
    // TODO: replace 16 with cipher_block_size
    var ciphertextAES: UnsafeMutablePointer<UInt8>? = nil
    defer {
        ciphertextAES?.deallocate(capacity: plaintext.count + 16 - 1)
    }
    
    var ciphertextLength: Int32 = 0
    
    var decryptedtext: UnsafeMutablePointer<UInt8>? = nil
    defer {
        decryptedtext?.deallocate(capacity: plaintext.count + 16 - 1)
    }
    let decryptedtextLength: Int32
    
    
    let status = u.generateAESKey(of: AES_KEYLEN_Bytes)
    guard status == true else {
        print("ERROR: generateAESKey")
        exit(0)
    }
    
    (ciphertextAES, ciphertextLength) = u.evpAESEncrypt(plaintext: plaintext)
    
    if let cipher = ciphertextAES {
        let encrypted_str = String(cString: UnsafePointer(cipher))
        print("Ciphertext (\(ciphertextLength))= \(encrypted_str)")
        
        (decryptedtext, decryptedtextLength) = u.evpAESDecrypt(ciphertext: cipher, cipherLength: ciphertextLength)
        if let decryptedtext = decryptedtext {
            let decrypted_str = String(cString: UnsafePointer(decryptedtext))
//            print("DECRYPTED (\(decryptedtextLength))= \(decrypted_str.data(using: .utf8)?.hexEncodedString() ?? "NULL")")
            print("Final AES decryption (\(decryptedtextLength)) = \(decrypted_str)")
        } else {
            print("ERROR: evpAESDecrypt")
        }
        
    } else {
        print("ERROR: evpAESEncrypt")
    }
}

func testRSAEnv(with plaintext: String) {

    let v = myRSA()
    
    var status = v.evpRSAInit()
    guard status == true else {
        print("ERROR: evpRSAInit")
        exit(0)
    }
    
    var ciphertextRSA: UnsafeMutablePointer<UInt8>? = nil
    defer {
        ciphertextRSA?.deallocate(capacity: plaintext.count + 16 - 1)
    }
    var ciphertextRSALength: Int32 = 0
    
    var encKey: UnsafeMutablePointer<UInt8>? = nil
    defer {
        encKey?.deallocate(capacity: plaintext.count + 16 - 1)
    }
    var encKeyLength: Int32 = 0
    
    var iv: UnsafeMutablePointer<UInt8>? = nil
    defer {
        iv?.deallocate(capacity: Int(EVP_MAX_IV_LENGTH))
    }
    var ivLength: Int32 = 0
    
    var decryptedtextRSA: UnsafeMutablePointer<UInt8>? = nil
    defer {
        decryptedtextRSA?.deallocate(capacity: plaintext.count + 16 - 1)
    }
    var decryptedtextRSALength: Int32 = 0
    
    status = v.generateRSAKey()
    guard status == true else {
        print("ERROR: generateRSAKey")
        exit(0)
    }
    
    ( ciphertextRSA, ciphertextRSALength, encKey, encKeyLength, iv, ivLength ) = v.rsaEncrypt(plaintext: plaintext)
    
    if let cipher = ciphertextRSA, let ek = encKey, let iv = iv {
        
        (decryptedtextRSA, decryptedtextRSALength) = v.rsaDecryption(ciphertext: cipher, cipherLength: ciphertextRSALength, encKey: ek, encKeyLength: encKeyLength, IV: iv, IVLength: ivLength )
        guard decryptedtextRSA != nil else {
            print("ERROR: rsaDecryption failed")
            exit(0)
        }
        let decrypted_str = String(cString: UnsafePointer(decryptedtextRSA!))
        print("Final RSA decryption (\(decryptedtextRSALength)) = \(decrypted_str)")
        
    } else {
        print("NULL")
    }
    
    
    
    v.evpRSADeinit()
}

main()


