package commonManagers

import (
)

/*
func TestBoxSeal(t *testing.T) {
	k, _ := newKMS(t)
	_, rec1PubKey, err := k.CreateAndExportPubKeyBytes(kms.ED25519)
	require.NoError(t, err)

	rec1EncPubKey, err := cryptoutil.PublicEd25519toCurve25519(rec1PubKey)
	require.NoError(t, err)

	b, err := NewCryptoBox(k)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, rec1EncPubKey, rand.Reader)
		require.NoError(t, err)
		dec, err := b.SealOpen(enc, rec1PubKey)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})

	t.Run("Failed decrypt, key missing from KMS", func(t *testing.T) {
		msg := []byte("pretend this is an encrypted message")

		_, err := b.SealOpen(msg, base58.Decode("BADKEY23452345234523452345"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "sealOpen: failed to exportPriveKeyBytes: getKeySet: "+
			"failed to read json keyset from reader")
	})

	t.Run("Failed decrypt, short message", func(t *testing.T) {
		enc := []byte("Bad message")

		_, err := b.SealOpen(enc, rec1PubKey)
		require.EqualError(t, err, "message too short")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := b.Seal(msg, rec1EncPubKey, rand.Reader)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = b.SealOpen(enc, rec1PubKey)
		require.EqualError(t, err, "failed to unpack")
	})
}
*/