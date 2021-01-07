package commonManagers

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/crypto/sha3"
	"hash"
	"net/http"
	"strings"
)

func GetHashLegacySHA1AsHexString(bytes []byte) string {
	digestValue, _ := GetDigestValue("SHA1", bytes)
	return digestValue
}

// The Keccak team recommends SHAKE256 for most applications upgrading from SHA2-512 (at least 64 bytes, variable length)
// instead of using SHA3-256 ("drop-in" replacement for SHA2-256 but with 32 bytes, fixed length)
// but currently only fixed-length SHA-3 algorithms (not SHAKE) are approved by NIST as alternative to the SHA-2 hash functions
// and NIST chose the stronger, but much slower, sponge instance for SHA3-512 (64 bytes fixed length).

func GetHashKeccakShake256AsHexString(bytes []byte) string {
	shake256Hash := GetHashKeccakShake256Bytes(bytes) // SHAKE256 has an arbitrary output length of at least 64 bytes
	shake256ResultHexString := hex.EncodeToString(shake256Hash)
	fmt.Printf("SHAKE256 bytes encoded to string in hex format= %s \n", shake256ResultHexString)
	return shake256ResultHexString
}

func GetHashKeccakShake256Bytes(bytes []byte) []byte {
	shake256Hash := make([]byte, 64)		// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	sha3.ShakeSum256(shake256Hash, bytes)	// Compute a 64-byte hash of buf and put it in shake256Hash.
	return shake256Hash
}

func GetHashSHA3256AsHexString(bytes []byte) string {
	digestValue, _ := GetDigestValue("SHA3256", bytes)
	return digestValue
}

// GetDigestValue returns the digest of some data, using a specified algorithm.
// It only returns an error when an invalid algorithm is used.
// The valid ones are: SHA1, SHA256, SHA512, SHA3256, and SHA3512.
func GetDigestValue(algorithm string, data []byte) (digestValue string, err error) {
	var hasher hash.Hash
	switch strings.ToUpper(algorithm) {
	// case "MD5": hasher = md5.New()
	case "SHA1": hasher = sha1.New()
	case "SHA256": hasher = sha256.New()
	case "SHA512": hasher = sha512.New()
	case "SHA3256": hasher = sha3.New256()
	case "SHA3512": hasher = sha3.New512()
	default:
		msg := "Invalid algorithm parameter passed go Checksum: %s"
		return digestValue, fmt.Errorf(msg, algorithm)
	}
	hasher.Write(data)
	digestBytes := hasher.Sum(nil)
	digestValue = hex.EncodeToString(digestBytes)
	return digestValue, nil
}

// ZKP returns an http.Handler that computes an interactive zero-knowledge proof-of-posession protocol.
func ZKP(fileBytes []byte) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// fileBytes, err := ioutil.ReadFile(fn)
		challengeString := r.Header.Get("x-zkp-challenge")
		if challengeString == "" {
			glog.Infof("didn't receive a challenge, so using a raw hash")
			digestBytes := make([]byte, 64)
			sha3.ShakeSum256(digestBytes, fileBytes)
			w.Write(digestBytes)
			return
		}
		challengeBytes := []byte(challengeString)
		glog.Infof("received a challenge of length %d", len(challengeBytes))
		hasher := sha3.New512()
		hasher.Write(challengeBytes)
		hasher.Write(fileBytes)
		digestBytes := make([]byte, 64)
		hasher.Sum(digestBytes)
		w.Write(digestBytes)
		return	// digest value in bytes of the sum: challenge + file
	}
}