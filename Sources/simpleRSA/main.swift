import Foundation


let v = myRSA()
_ = v.evpRSAInit()


let plaintext = "The Swift Programming Language (Swift 4)"


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

_ = v.evpAESEncrypt(plaintext: plaintext, ciphertext: &ciphertextAES, cipherLength: &ciphertextLength)


if let cipher = ciphertextAES {
    let encrypted_str = String(cString: UnsafePointer(cipher))
    print("Ciphertext (\(ciphertextLength))= \(encrypted_str)")
    
    _ = v.evpAESDecrypt(ciphertext: cipher, cipherLength: ciphertextLength, decMsg: &decryptedtext, decMsgLen: &decryptedtextLength)


} else {
    print("NULL")
}


