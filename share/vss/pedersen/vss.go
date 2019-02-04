// Package vss implements the verifiable secret sharing scheme from
// "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"
// by Torben Pryds Pedersen.
// https://link.springer.com/content/pdf/10.1007/3-540-46766-1_9.pdf
package vss

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/share"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/protobuf"
)

// Suite defines the capabilities required by the vss package.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// Dealer encapsulates for creating and distributing the shares and for
// replying to any Responses.
type Dealer struct {
	suite  Suite
	reader cipher.Stream
	// long is the longterm key of the Dealer
	long          kyber.Scalar
	pub           kyber.Point
	secret        kyber.Scalar
	secretCommits []kyber.Point
	secretPoly    *share.PriPoly
	verifiers     []kyber.Point
	hkdfContext   []byte
	// threshold of shares that is needed to reconstruct the secret
	t int
	// sessionID is a unique identifier for the whole session of the scheme
	sessionID []byte
	// list of deals this Dealer has generated
	deals []*Deal
	*Aggregator
}

// Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
type Deal struct {
	// Unique session identifier for this protocol run
	SessionID []byte
	// Private share generated by the dealer
	SecShare *share.PriShare
	// Threshold used for this secret sharing run
	T uint32
	// Commitments are the coefficients used to verify the shares against
	Commitments []kyber.Point
}

// EncryptedDeal contains the deal in a encrypted form only decipherable by the
// correct recipient. The encryption is performed in a similar manner as what is
// done in TLS. The dealer generates a temporary key pair, signs it with its
// longterm secret key.
type EncryptedDeal struct {
	// Ephemeral Diffie Hellman key
	DHKey []byte
	// Signature of the DH key by the longterm key of the dealer
	Signature []byte
	// Nonce used for the encryption
	Nonce []byte
	// AEAD encryption of the deal marshalled by protobuf
	Cipher []byte
}

// Response is sent by the verifiers to all participants and holds each
// individual validation or refusal of a Deal.
type Response struct {
	// SessionID related to this run of the protocol
	SessionID []byte
	// Index of the verifier issuing this Response from the new set of nodes
	Index uint32
	// false = NO APPROVAL == Complaint , true = APPROVAL
	Status bool
	// Signature over the whole packet
	Signature []byte
}

const (
	// StatusComplaint is a constant value meaning that a verifier issues
	// a Complaint against its Dealer.
	StatusComplaint bool = false
	// StatusApproval is a constant value meaning that a verifier agrees with
	// the share it received.
	StatusApproval bool = true
)

// Justification is a message that is broadcasted by the Dealer in response to
// a Complaint. It contains the original Complaint as well as the shares
// distributed to the complainer.
type Justification struct {
	// SessionID related to the current run of the protocol
	SessionID []byte
	// Index of the verifier who issued the Complaint,i.e. index of this Deal
	Index uint32
	// Deal in cleartext
	Deal *Deal
	// Signature over the whole packet
	Signature []byte
}

// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
// does not have to be trusted by other Verifiers. The security parameter t is
// the number of shares required to reconstruct the secret. It is HIGHLY
// RECOMMENDED to use a threshold higher or equal than what the method
// MinimumT() returns, otherwise it breaks the security assumptions of the whole
// scheme. It returns an error if the t is less than or equal to 2.
func NewDealer(suite Suite, longterm, secret kyber.Scalar, verifiers []kyber.Point, t int) (*Dealer, error) {
	d := &Dealer{
		suite:     suite,
		long:      longterm,
		secret:    secret,
		verifiers: verifiers,
	}
	if !validT(t, verifiers) {
		return nil, fmt.Errorf("dealer: t %d invalid", t)
	}
	d.t = t

	f := share.NewPriPoly(d.suite, d.t, d.secret, suite.RandomStream())
	d.pub = d.suite.Point().Mul(d.long, nil)

	// Compute public polynomial coefficients
	F := f.Commit(d.suite.Point().Base())
	_, d.secretCommits = F.Info()

	var err error
	d.sessionID, err = sessionID(d.suite, d.pub, d.verifiers, d.secretCommits, d.t)
	if err != nil {
		return nil, err
	}

	d.Aggregator = newAggregator(d.suite, d.pub, d.verifiers, d.secretCommits, d.t, d.sessionID)
	// C = F + G
	d.deals = make([]*Deal, len(d.verifiers))
	for i := range d.verifiers {
		fi := f.Eval(i)
		d.deals[i] = &Deal{
			SessionID:   d.sessionID,
			SecShare:    fi,
			Commitments: d.secretCommits,
			T:           uint32(d.t),
		}
	}
	d.hkdfContext = context(suite, d.pub, verifiers)
	d.secretPoly = f
	return d, nil
}

// PlaintextDeal returns the plaintext version of the deal destined for peer i.
// Use this only for testing.
func (d *Dealer) PlaintextDeal(i int) (*Deal, error) {
	if i >= len(d.deals) {
		return nil, errors.New("dealer: PlaintextDeal given wrong index")
	}
	return d.deals[i], nil
}

// EncryptedDeal returns the encryption of the deal that must be given to the
// verifier at index i.
// The dealer first generates a temporary Diffie Hellman key, signs it using its
// longterm key, and computes the shared key depending on its longterm and
// ephemeral key and the verifier's public key.
// This shared key is then fed into a HKDF whose output is the key to a AEAD
// (AES256-GCM) scheme to encrypt the deal.
func (d *Dealer) EncryptedDeal(i int) (*EncryptedDeal, error) {
	vPub, ok := findPub(d.verifiers, uint32(i))
	if !ok {
		return nil, errors.New("dealer: wrong index to generate encrypted deal")
	}
	// gen ephemeral key
	dhSecret := d.suite.Scalar().Pick(d.suite.RandomStream())
	dhPublic := d.suite.Point().Mul(dhSecret, nil)
	// signs the public key
	dhPublicBuff, _ := dhPublic.MarshalBinary()
	signature, err := schnorr.Sign(d.suite, d.long, dhPublicBuff)
	if err != nil {
		return nil, err
	}
	// AES128-GCM
	pre := dhExchange(d.suite, dhSecret, vPub)
	gcm, err := newAEAD(d.suite.Hash, pre, d.hkdfContext)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	dealBuff, err := d.deals[i].MarshalBinary()
	if err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nil, nonce, dealBuff, d.hkdfContext)
	dhBytes, _ := dhPublic.MarshalBinary()
	return &EncryptedDeal{
		DHKey:     dhBytes,
		Signature: signature,
		Nonce:     nonce,
		Cipher:    encrypted,
	}, nil
}

// EncryptedDeals calls `EncryptedDeal` for each index of the verifier and
// returns the list of encrypted deals. Each index in the returned slice
// corresponds to the index in the list of verifiers.
func (d *Dealer) EncryptedDeals() ([]*EncryptedDeal, error) {
	deals := make([]*EncryptedDeal, len(d.verifiers))
	var err error
	for i := range d.verifiers {
		deals[i], err = d.EncryptedDeal(i)
		if err != nil {
			return nil, err
		}
	}
	return deals, nil
}

// ProcessResponse analyzes the given Response. If it's a valid complaint, then
// it returns a Justification. This Justification must be broadcasted to every
// participants. If it's an invalid complaint, it returns an error about the
// complaint. The verifiers will also ignore an invalid Complaint.
func (d *Dealer) ProcessResponse(r *Response) (*Justification, error) {
	if err := d.verifyResponse(r); err != nil {
		return nil, err
	}
	if r.Status == StatusApproval {
		return nil, nil
	}

	j := &Justification{
		SessionID: d.sessionID,
		// index is guaranteed to be good because of d.verifyResponse before
		Index: r.Index,
		Deal:  d.deals[int(r.Index)],
	}
	sig, err := schnorr.Sign(d.suite, d.long, j.Hash(d.suite))
	if err != nil {
		return nil, err
	}
	j.Signature = sig
	return j, nil
}

// SecretCommit returns the commitment of the secret being shared by this
// dealer. This function is only to be called once the deal has enough approvals
// and is verified otherwise it returns nil.
func (d *Dealer) SecretCommit() kyber.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.suite.Point().Mul(d.secret, nil)
}

// Commits returns the commitments of the coefficient of the secret polynomial
// the Dealer is sharing.
func (d *Dealer) Commits() []kyber.Point {
	return d.secretCommits
}

// Key returns the longterm key pair used by this Dealer.
func (d *Dealer) Key() (secret kyber.Scalar, public kyber.Point) {
	return d.long, d.pub
}

// SessionID returns the current sessionID generated by this dealer for this
// protocol run.
func (d *Dealer) SessionID() []byte {
	return d.sessionID
}

// SetTimeout marks the end of a round, invalidating any missing (or future) response
// for this DKG protocol round. The caller is expected to call this after a long timeout
// so each DKG node can still compute its share if enough Deals are valid.
func (d *Dealer) SetTimeout() {
	d.Aggregator.cleanVerifiers()
}

// PrivatePoly returns the private polynomial used to generate the deal. This
// private polynomial can be saved and then later on used to generate new
// shares.  This information SHOULD STAY PRIVATE and thus MUST never be given
// to any third party.
func (d *Dealer) PrivatePoly() *share.PriPoly {
	return d.secretPoly
}

// Verifier receives a Deal from a Dealer, can reply with a Complaint, and can
// collaborate with other Verifiers to reconstruct a secret.
type Verifier struct {
	suite       Suite
	longterm    kyber.Scalar
	pub         kyber.Point
	dealer      kyber.Point
	index       int
	verifiers   []kyber.Point
	hkdfContext []byte
	*Aggregator
}

// NewVerifier returns a Verifier out of:
//   - its longterm secret key
//   - the longterm dealer public key
//   - the list of public key of verifiers. The list MUST include the public key of this Verifier also.
// The security parameter t of the secret sharing scheme is automatically set to
// a default safe value. If a different t value is required, it is possible to set
// it with `verifier.SetT()`.
func NewVerifier(suite Suite, longterm kyber.Scalar, dealerKey kyber.Point,
	verifiers []kyber.Point) (*Verifier, error) {

	pub := suite.Point().Mul(longterm, nil)
	var ok bool
	var index int
	for i, v := range verifiers {
		if v.Equal(pub) {
			ok = true
			index = i
			break
		}
	}
	if !ok {
		return nil, errors.New("vss: public key not found in the list of verifiers")
	}
	v := &Verifier{
		suite:       suite,
		longterm:    longterm,
		dealer:      dealerKey,
		verifiers:   verifiers,
		pub:         pub,
		index:       index,
		hkdfContext: context(suite, dealerKey, verifiers),
		Aggregator:  NewEmptyAggregator(suite, verifiers),
	}
	return v, nil
}

// ProcessEncryptedDeal decrypt the deal received from the Dealer.
// If the deal is valid, i.e. the verifier can verify its shares
// against the public coefficients and the signature is valid, an approval
// response is returned and must be broadcasted to every participants
// including the dealer.
// If the deal itself is invalid, it returns a complaint response that must be
// broadcasted to every other participants including the dealer.
// If the deal has already been received, or the signature generation of the
// response failed, it returns an error without any responses.
func (v *Verifier) ProcessEncryptedDeal(e *EncryptedDeal) (*Response, error) {
	d, err := v.decryptDeal(e)
	if err != nil {
		return nil, err
	}
	if d.SecShare.I != v.index {
		return nil, errors.New("vss: verifier got wrong index from deal")
	}

	t := int(d.T)

	sid, err := sessionID(v.suite, v.dealer, v.verifiers, d.Commitments, t)
	if err != nil {
		return nil, err
	}

	r := &Response{
		SessionID: sid,
		Index:     uint32(v.index),
		Status:    StatusApproval,
	}
	if err = v.VerifyDeal(d, true); err != nil {
		r.Status = StatusComplaint
	}

	if err == errDealAlreadyProcessed {
		return nil, err
	}

	if r.Signature, err = schnorr.Sign(v.suite, v.longterm, r.Hash(v.suite)); err != nil {
		return nil, err
	}

	if err = v.Aggregator.addResponse(r); err != nil {
		return nil, err
	}
	return r, nil
}

func (v *Verifier) decryptDeal(e *EncryptedDeal) (*Deal, error) {
	// verify signature
	if err := schnorr.Verify(v.suite, v.dealer, e.DHKey, e.Signature); err != nil {
		return nil, err
	}

	// compute shared key and AES526-GCM cipher
	dhKey := v.suite.Point()
	if err := dhKey.UnmarshalBinary(e.DHKey); err != nil {
		return nil, err
	}
	pre := dhExchange(v.suite, v.longterm, dhKey)
	gcm, err := newAEAD(v.suite.Hash, pre, v.hkdfContext)
	if err != nil {
		return nil, err
	}
	decrypted, err := gcm.Open(nil, e.Nonce, e.Cipher, v.hkdfContext)
	if err != nil {
		return nil, err
	}
	deal := &Deal{}
	err = deal.UnmarshalBinary(v.suite, decrypted)
	return deal, err
}

// ErrNoDealBeforeResponse is an error returned if a verifier receives a
// deal before having received any responses. For the moment, the caller must
// be sure to have dispatched a deal before.
var ErrNoDealBeforeResponse = errors.New("verifier: need to receive deal before response")

// ProcessResponse analyzes the given response. If it's a valid complaint, the
// verifier should expect to see a Justification from the Dealer. It returns an
// error if it's not a valid response.
// Call `v.DealCertified()` to check if the whole protocol is finished.
func (v *Verifier) ProcessResponse(resp *Response) error {
	if v.Aggregator.deal == nil {
		return ErrNoDealBeforeResponse
	}
	return v.Aggregator.verifyResponse(resp)
}

// Commits returns the commitments of the coefficients of the polynomial
// contained in the Deal received. It is public information. The private
// information in the deal must be retrieved through Deal().
func (v *Verifier) Commits() []kyber.Point {
	return v.deal.Commitments
}

// Deal returns the Deal that this verifier has received. It returns
// nil if the deal is not certified or there is not enough approvals.
func (v *Verifier) Deal() *Deal {
	if !v.EnoughApprovals() || !v.DealCertified() {
		return nil
	}
	return v.deal
}

// ProcessJustification takes a DealerResponse and returns an error if
// something went wrong during the verification. If it is the case, that
// probably means the Dealer is acting maliciously. In order to be sure, call
// `v.EnoughApprovals()` and if true, `v.DealCertified()`.
func (v *Verifier) ProcessJustification(dr *Justification) error {
	return v.Aggregator.verifyJustification(dr)
}

// Key returns the longterm key pair this verifier is using during this protocol
// run.
func (v *Verifier) Key() (kyber.Scalar, kyber.Point) {
	return v.longterm, v.pub
}

// Index returns the index of the verifier in the list of participants used
// during this run of the protocol.
func (v *Verifier) Index() int {
	return v.index
}

// SessionID returns the session id generated by the Dealer. It returns
// an nil slice if the verifier has not received the Deal yet.
func (v *Verifier) SessionID() []byte {
	return v.sid
}

// RecoverSecret recovers the secret shared by a Dealer by gathering at least t
// Deals from the verifiers. It returns an error if there is not enough Deals or
// if all Deals don't have the same SessionID.
func RecoverSecret(suite Suite, deals []*Deal, n, t int) (kyber.Scalar, error) {
	shares := make([]*share.PriShare, len(deals))
	for i, deal := range deals {
		// all sids the same
		if bytes.Equal(deal.SessionID, deals[0].SessionID) {
			shares[i] = deal.SecShare
		} else {
			return nil, errors.New("vss: all deals need to have same session id")
		}
	}
	return share.RecoverSecret(suite, shares, t, n)
}

// SetTimeout marks the end of a round, invalidating any missing (or future) response
// for this DKG protocol round. The caller is expected to call this after a long timeout
// so each DKG node can still compute its share if enough Deals are valid.
func (v *Verifier) SetTimeout() {
	v.Aggregator.cleanVerifiers()
}

// UnsafeSetResponseDKG is an UNSAFE bypass method to allow DKG to use VSS
// that works on basis of approval only.
func (v *Verifier) UnsafeSetResponseDKG(idx uint32, approval bool) {
	r := &Response{
		SessionID: v.Aggregator.sid,
		Index:     uint32(idx),
		Status:    approval,
	}

	v.Aggregator.addResponse(r)
}

// Aggregator is used to collect all deals, and responses for one protocol run.
// It brings common functionalities for both Dealer and Verifier structs.
type Aggregator struct {
	suite     Suite
	dealer    kyber.Point
	verifiers []kyber.Point
	commits   []kyber.Point

	responses map[uint32]*Response
	sid       []byte
	deal      *Deal
	t         int
	badDealer bool
}

func newAggregator(suite Suite, dealer kyber.Point, verifiers, commitments []kyber.Point, t int, sid []byte) *Aggregator {
	agg := &Aggregator{
		suite:     suite,
		dealer:    dealer,
		verifiers: verifiers,
		commits:   commitments,
		t:         t,
		sid:       sid,
		responses: make(map[uint32]*Response),
	}
	return agg
}

// NewEmptyAggregator returns a structure capable of storing Responses about a
// deal and check if the deal is certified or not.
func NewEmptyAggregator(suite Suite, verifiers []kyber.Point) *Aggregator {
	return &Aggregator{
		suite:     suite,
		verifiers: verifiers,
		responses: make(map[uint32]*Response),
	}
}

var errDealAlreadyProcessed = errors.New("vss: verifier already received a deal")

// VerifyDeal analyzes the deal and returns an error if it's incorrect. If
// inclusion is true, it also returns an error if it is the second time this struct
// analyzes a Deal.
func (a *Aggregator) VerifyDeal(d *Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return errDealAlreadyProcessed

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
		a.t = int(d.T)
	}

	if !validT(int(d.T), a.verifiers) {
		return errors.New("vss: invalid t received in Deal")
	}

	if int(d.T) != a.t {
		return errors.New("vss: incompatible threshold - potential attack")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("vss: find different sessionIDs from Deal")
	}

	fi := d.SecShare
	if fi.I < 0 || fi.I >= len(a.verifiers) {
		return errors.New("vss: index out of bounds in Deal")
	}
	// compute fi * G
	fig := a.suite.Point().Base().Mul(fi.V, nil)

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !fig.Equal(pubShare.V) {
		return errors.New("vss: share does not verify against commitments in Deal")
	}
	return nil
}

// cleanVerifiers checks the Aggregator's response array and creates a
// StatusComplaint response for all verifiers that did not respond to the Deal.
func (a *Aggregator) cleanVerifiers() {
	for i := range a.verifiers {
		if _, ok := a.responses[uint32(i)]; !ok {
			a.responses[uint32(i)] = &Response{
				SessionID: a.sid,
				Index:     uint32(i),
				Status:    StatusComplaint,
			}
		}
	}
}

// SetThreshold is used to specify the expected threshold *before* the verifier
// receives anything. Sometimes, a verifier knows the treshold in advance and
// should make sure the one it receives from the dealer is consistent. If this
// method is not called, the first threshold received is considered as the
// "truth".
func (a *Aggregator) SetThreshold(t int) {
	a.t = t
}

// ProcessResponse verifies the validity of the given response and stores it
// internall. It is  the public version of verifyResponse created this way to
// allow higher-level package to use these functionalities.
func (a *Aggregator) ProcessResponse(r *Response) error {
	return a.verifyResponse(r)
}

func (a *Aggregator) verifyResponse(r *Response) error {
	if a.sid != nil && !bytes.Equal(r.SessionID, a.sid) {
		return errors.New("vss: receiving inconsistent sessionID in response")
	}

	pub, ok := findPub(a.verifiers, r.Index)
	if !ok {
		return errors.New("vss: index out of bounds in response")
	}

	if err := schnorr.Verify(a.suite, pub, r.Hash(a.suite), r.Signature); err != nil {
		return err
	}

	return a.addResponse(r)
}

func (a *Aggregator) verifyJustification(j *Justification) error {
	if _, ok := findPub(a.verifiers, j.Index); !ok {
		return errors.New("vss: index out of bounds in justification")
	}
	r, ok := a.responses[j.Index]
	if !ok {
		return errors.New("vss: no complaints received for this justification")
	}
	if r.Status != StatusComplaint {
		return errors.New("vss: justification received for an approval")
	}

	if err := a.VerifyDeal(j.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		a.badDealer = true
		return err
	}
	r.Status = StatusApproval
	return nil
}

func (a *Aggregator) addResponse(r *Response) error {
	if _, ok := findPub(a.verifiers, r.Index); !ok {
		return errors.New("vss: index out of bounds in Complaint")
	}
	if _, ok := a.responses[r.Index]; ok {
		return errors.New("vss: already existing response from same origin")
	}
	a.responses[r.Index] = r
	return nil
}

// EnoughApprovals returns true if enough verifiers have sent their approval for
// the deal they received.
func (a *Aggregator) EnoughApprovals() bool {
	var app int
	for _, r := range a.responses {
		if r.Status == StatusApproval {
			app++
		}
	}
	//fmt.Println("enoughApproval ", app, " >= ", a.t, " -> ", app >= a.t)
	return app >= a.t
}

// Responses returns the list of responses received and processed by this
// aggregator
func (a *Aggregator) Responses() map[uint32]*Response {
	return a.responses
}

// DealCertified returns true if there has been less than t complaints, all
// Justifications were correct and if EnoughApprovals() returns true.
func (a *Aggregator) DealCertified() bool {
	var absentVerifiers int
	var complaints int

	// Check either a StatusApproval or StatusComplaint for all known verifiers
	// i.e. make sure all verifiers are either timed-out or OK.
	for i := range a.verifiers {
		if r, ok := a.responses[uint32(i)]; !ok {
			absentVerifiers++
		} else if r.Status == StatusComplaint {
			complaints++
		}
	}

	tooMuchComplaints := absentVerifiers > 0 || a.badDealer || complaints > a.t
	return a.EnoughApprovals() && !tooMuchComplaints
}

// MinimumT returns the minimum safe T that is proven to be secure with this
// protocol. It expects n, the total number of participants.
// WARNING: Setting a lower T could make
// the whole protocol insecure. Setting a higher T only makes it harder to
// reconstruct the secret.
func MinimumT(n int) int {
	return (n + 1) / 2
}

func validT(t int, verifiers []kyber.Point) bool {
	return t >= 2 && t <= len(verifiers) && int(uint32(t)) == t
}

func deriveH(suite Suite, verifiers []kyber.Point) kyber.Point {
	var b bytes.Buffer
	for _, v := range verifiers {
		_, _ = v.MarshalTo(&b)
	}
	base := suite.Point().Pick(suite.XOF(b.Bytes()))
	return base
}

func findPub(verifiers []kyber.Point, idx uint32) (kyber.Point, bool) {
	iidx := int(idx)
	if iidx >= len(verifiers) {
		return nil, false
	}
	return verifiers[iidx], true
}

func sessionID(suite Suite, dealer kyber.Point, verifiers, commitments []kyber.Point, t int) ([]byte, error) {
	h := suite.Hash()
	_, _ = dealer.MarshalTo(h)

	for _, v := range verifiers {
		_, _ = v.MarshalTo(h)
	}

	for _, c := range commitments {
		_, _ = c.MarshalTo(h)
	}
	_ = binary.Write(h, binary.LittleEndian, uint32(t))

	return h.Sum(nil), nil
}

// Hash returns the Hash representation of the Response
func (r *Response) Hash(s Suite) []byte {
	h := s.Hash()
	_, _ = h.Write([]byte("response"))
	_, _ = h.Write(r.SessionID)
	_ = binary.Write(h, binary.LittleEndian, r.Index)
	_ = binary.Write(h, binary.LittleEndian, r.Status)
	return h.Sum(nil)
}

// MarshalBinary returns the binary representations of a Deal.
// The encryption of a deal operates on this binary representation.
func (d *Deal) MarshalBinary() ([]byte, error) {
	return protobuf.Encode(d)
}

// UnmarshalBinary reads the Deal from the binary represenstation.
func (d *Deal) UnmarshalBinary(s Suite, buff []byte) error {
	constructors := make(protobuf.Constructors)
	var point kyber.Point
	var secret kyber.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return s.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return s.Scalar() }
	return protobuf.DecodeWithConstructors(buff, d, constructors)
}

// Hash returns the hash of a Justification.
func (j *Justification) Hash(s Suite) []byte {
	h := s.Hash()
	_, _ = h.Write([]byte("justification"))
	_, _ = h.Write(j.SessionID)
	_ = binary.Write(h, binary.LittleEndian, j.Index)
	buff, _ := j.Deal.MarshalBinary()
	_, _ = h.Write(buff)
	return h.Sum(nil)
}
