# simpleCrypto


swift build -Xlinker -L/usr/local/opt/openssl/lib -Xcc -I/usr/local/opt/openssl/include

# To build in Xcode:

`swift package generate-xcodeproj`

go to targets ->
build settings ->
search for user paths
add to Header Search Paths /usr/local/opt/openssl/include
add to Library Search Paths /usr/local/opt/openssl/lib

Build magic.


