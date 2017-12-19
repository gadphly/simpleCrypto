import Foundation
import OpenSSL

func main() throws {
//    try v.readRSAKey()
    
    let plaintext = "In those days spirits were brave, the stakes were high, men were real men, women were real women and small furry creatures from Alpha Centauri were real small furry creatures from Alpha Centauri."
//    let plaintext = "In those days"

    testRSASign(with: plaintext)

//    print("Original plaintext (\(plaintext.count)) = " + plaintext + "\n\n")
//    testAESEnv(with: plaintext)
//    testRSAEnv(with: plaintext)

}

func testAESEnv(with plaintext: String) {
    
    let AES_KEYLEN_Bytes = 16 //256 bits
    let u = myAES()

    // AES ciphertext has range [0 ... (inl + cipher_block_size - 1) ]
    // TODO: replace 16 with cipher_block_size
    var ciphertextAES: Data?
    var decryptedtext: Data?
    
    let status = u.generateAESKey(of: AES_KEYLEN_Bytes)
    guard status == true else {
        print("ERROR: generateAESKey")
        exit(0)
    }
    
    ciphertextAES = u.evpAESEncrypt(plaintext: plaintext)!
    
    if let cipher = ciphertextAES {
        print("Ciphertext (\(cipher.count))= \(cipher.hexEncodedString())\n\n")
        
        decryptedtext = u.evpAESDecrypt(ciphertext: cipher)
        if let decryptedtext = decryptedtext {
            print("Final AES decryption (\(decryptedtext.count)) = \(String(data: decryptedtext, encoding: String.Encoding.utf8) ?? "NULL")")
        } else {
            print("ERROR: evpAESDecrypt")
        }

        if ( decryptedtext == Data(bytes: plaintext, count: plaintext.count) ) {
            print("\n\nHey congrats! You have successfully encrypted-then-decrypted a string with AES256!\nWhat's next on your bucket list?\n\n")
        } else {
            print("\n\n¯\\_(ツ)_/¯ You _still_ can't encrypt/decrypt with AES256 ")
        }
        
    } else {
        print("ERROR: evpAESEncrypt")
    }
}

func testReadRSAKeys() {
    let v = myRSA()
    do {
        try v.readRSAKey()
    }
    catch {
        print("FAILURE is not an option")
    }
}

func testRSASign(with message: String) {
    let v = myRSA()

    guard v.generateRSAKey() == true else {
        print("ERROR: generateRSAKey")
        exit(0)
    }

//    if let signature = v.evpDigestSignVerifyCustom(of: message) {
    if let signature = v.evpDigestSignVerifyVanilla(of: message) {
        print("signature (\(signature.count)) = \(signature.hexEncodedString())")
    }
}


func testRSAEnv(with plaintext: String) {

    let v = myRSA()
    
    var status = v.evpRSAInit()
    guard status == true else {
        print("ERROR: evpRSAInit")
        exit(0)
    }
    
    var ciphertextRSA: Data?
    var encKey: Data?
    var iv: Data?
    var decryptedtextRSA: Data?

    status = v.generateRSAKey()
    guard status == true else {
        print("ERROR: generateRSAKey")
        exit(0)
    }
    
    ( ciphertextRSA, encKey, iv ) = v.rsaEncrypt(plaintext: plaintext)
    
    if let cipher = ciphertextRSA, let ek = encKey, let iv = iv {
        print("Ciphertext (\(cipher.count)) = \(cipher.hexEncodedString())")
        print("Encrypted AES256 key (\(ek.count)) = \(ek.hexEncodedString())")
        print("IV (\(iv.count)) = \(iv.hexEncodedString())\n\n")

        decryptedtextRSA = v.rsaDecryption(ciphertext: cipher, encKey: ek, IV: iv )
        if let decryptedtextRSA = decryptedtextRSA {
            print("Final RSA decryption (\(decryptedtextRSA.count)) = \(String(data: decryptedtextRSA, encoding: String.Encoding.utf8) ?? "NULL")\n\n")
        } else {
            print("ERROR: rsaDecryption")
        }
        
        if ( decryptedtextRSA == Data(bytes: plaintext, count: plaintext.count) ) {
            print("\n\nHey congrats! You have successfully encrypted-then-decrypted a string with RSA-EVP_aes_256_cbc!\nWhat's next on your bucket list?\n\n")
        } else {
            print("\n\n¯\\_(ツ)_/¯ You _still_ can't encrypt/decrypt with RSA-EVP_aes_256_cbc ")
        }

    } else {
        print("NULL")
    }
    
    v.evpRSADeinit()
}

try main()


