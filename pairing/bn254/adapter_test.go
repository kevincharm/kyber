package bn254

import (
	"testing"

	"github.com/drand/kyber/util/key"
	"github.com/stretchr/testify/require"
)

func TestAdapter_SuiteBn254(t *testing.T) {
	suite := NewSuiteBn254()

	pair := key.NewKeyPair(suite)
	pubkey, err := pair.Public.MarshalBinary()
	require.Nil(t, err)
	privkey, err := pair.Private.MarshalBinary()
	require.Nil(t, err)

	pubhex := suite.Point()
	err = pubhex.UnmarshalBinary(pubkey)
	require.Nil(t, err)

	privhex := suite.Scalar()
	err = privhex.UnmarshalBinary(privkey)
	require.Nil(t, err)

	require.Equal(t, "bn254.adapter", suite.String())
}
