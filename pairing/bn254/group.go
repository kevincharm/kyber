package bn254

import (
	"crypto/cipher"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
)

type groupG1 struct {
	common
	*commonSuite
	dst []byte
}

func (g *groupG1) String() string {
	return "bn254.G1"
}

func (g *groupG1) PointLen() int {
	return newPointG1(g.dst).MarshalSize()
}

func (g *groupG1) Point() kyber.Point {
	return newPointG1(g.dst)
}

type groupG2 struct {
	common
	*commonSuite
	dst []byte
}

func (g *groupG2) String() string {
	return "bn254.G2"
}

func (g *groupG2) PointLen() int {
	return newPointG2(g.dst).MarshalSize()
}

func (g *groupG2) Point() kyber.Point {
	return newPointG2(g.dst)
}

type groupGT struct {
	common
	*commonSuite
}

func (g *groupGT) String() string {
	return "bn254.GT"
}

func (g *groupGT) PointLen() int {
	return newPointGT().MarshalSize()
}

func (g *groupGT) Point() kyber.Point {
	return newPointGT()
}

// common functionalities across G1, G2, and GT
type common struct{}

func (c *common) ScalarLen() int {
	return mod.NewInt64(0, Order).MarshalSize()
}

func (c *common) Scalar() kyber.Scalar {
	return mod.NewInt64(0, Order)
}

func (c *common) PrimeOrder() bool {
	return true
}

func (c *common) NewKey(rand cipher.Stream) kyber.Scalar {
	return mod.NewInt64(0, Order).Pick(rand)
}
