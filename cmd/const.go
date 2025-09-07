/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

// File format
const (
	FormatUndefined       int = 0  // Not yet set
	FormatSha             int = 1  // SHA as truncated base64
	FormatShaMod          int = 2  // add: modify time as hex epoch time
	FormatShaModSize      int = 3  // add: size (dynamic) as hex in bytes
	FormatShaModSizeAnnot int = 4  // add: annotations (multiple)
	FormatAll             int = 5  // add: name with control code escapes     <= the default shaman format
	FormatCSV             int = 6  // Comma-separated hex SHA, decimal time+size  )
	FormatNativeBSDOSX    int = 7  // BSD/OSX format SHA256 output	              ) output
	FormatNativeOpenSSL   int = 8  // OpenSSL format SHA256 output	              ) only
	FormatNativeLinux     int = 9  // Linux format SHA256 output		          )
	FormatBinary          int = 10 // Blocks of SHA256 as 32-byte chunks          )
)

// The "empty hash"
// const emptySHAhex string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const emptySHAb64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
