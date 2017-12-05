import Foundation
import OpenSSL


let u = myAES()

let plaintext = "In those days spirits were brave, the stakes were high, men were real men, women were real women and small furry creatures from Alpha Centauri were real small furry creatures from Alpha Centauri."

let AES_KEYLEN_Bytes = 16 //256 bits

//var ciphertext =  String()
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

var decryptedtextLength: Int32 = 0

var status = u.generateAESKey(of: AES_KEYLEN_Bytes)
guard status == true else {
    print("ERROR: generateAESKey")
    exit(0)
}

status = u.evpAESEncrypt(plaintext: plaintext, ciphertext: &ciphertextAES, cipherLength: &ciphertextLength)
guard status == true else {
    print("ERROR: evpAESEncrypt")
    exit(0)
}


if let cipher = ciphertextAES {
    let encrypted_str = String(cString: UnsafePointer(cipher))
    print("Ciphertext (\(ciphertextLength))= \(encrypted_str)")
    
    status = u.evpAESDecrypt(ciphertext: cipher, cipherLength: ciphertextLength, decMsg: &decryptedtext, decMsgLen: &decryptedtextLength)
    guard status == true else {
        print("ERROR: evpAESDecrypt")
        exit(0)
    }

} else {
    print("NULL")
}

let v = myRSA()

status = v.evpRSAInit()
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

status = v.rsaEncrypt(plaintext: plaintext, ciphertext: &ciphertextRSA, cipherLength: &ciphertextRSALength, encKey: &encKey, encKeyLength: &encKeyLength, IV: &iv, IVLength: &ivLength)

if let cipher = ciphertextRSA, let ek = encKey, let iv = iv {
    let encrypted_str = String(cString: UnsafePointer(cipher))
    print("Ciphertext (\(ciphertextLength))= \(encrypted_str)")
    
    status = v.rsaDecryption(ciphertext: cipher, cipherLength: ciphertextRSALength, encKey: ek, encKeyLength: encKeyLength, IV: iv, IVLength: ivLength, decMsg: &decryptedtextRSA, decMsgLen: &decryptedtextRSALength)
    guard status == true else {
        print("ERROR: evpAESDecrypt")
        exit(0)
    }
    
} else {
    print("NULL")
}



v.evpRSADeinit()










