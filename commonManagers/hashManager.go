package commonManagers

import (
	"github.com/golang/glog"
	"golang.org/x/crypto/sha3"
	"net/http"
)

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