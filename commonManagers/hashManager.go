package commonManagers

import (
	"crypto/sha1"
	fmt "fmt"
)

func getHashLegacySHA1(bytes []byte) (string, error) {
	sha1 := sha1.New()
	sha1.Write(bytes)
	byteSlice := sha1.Sum(nil)
	fmt.Printf("SHA1 bytes in hex = %x \n", byteSlice)
	hexString := bytesToString(byteSlice)
	fmt.Printf("SHA1 hex bytes converted to string = %s \n", hexString)
	return hexString, nil
}
