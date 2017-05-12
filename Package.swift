import PackageDescription


#if os(Linux)
//    .Package(url: "https://github.com/gtaban/OpenSSL.git", majorVersion: 0)
var dependencies: [Package.Dependency] = [
    .Package(url: "https://github.com/IBM-Swift/OpenSSL.git", majorVersion: 0)
]
#else
    var dependencies: [Package.Dependency] = [
    .Package(url: "https://github.com/IBM-Swift/OpenSSL-OSX.git", majorVersion: 0)
]
#endif

let package = Package(
    name: "simpleRSA",
    dependencies: dependencies

)
