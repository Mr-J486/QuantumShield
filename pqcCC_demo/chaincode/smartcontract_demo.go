package chaincode

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// SmartContract provides functions for managing SignedEvent assets
type SmartContract struct {
	contractapi.Contract
}

// SignedEvent is the "asset" stored on-ledger (test phase: includes pub key + hash_b64)
type SignedEvent struct {
	ID      string          `json:"id"`       // ledger key (event_id or any unique id)
	Data    json.RawMessage `json:"data"`     // the event JSON (protected)
	HashB64 string          `json:"hash_b64"` // optional/debug; chaincode recomputes and can compare
	SigB64  string          `json:"sig_b64"`  // signature over SHA-256(JCS(data))
	SigAlgo string          `json:"sig_algo"` // e.g., "ML-DSA-65"
	PubB64  string          `json:"pub_b64"`  // public key (test phase only)
}

// VerifySignedEventPayload verifies signature (and optionally hash_b64 consistency).
// IMPORTANT: It recomputes hash from Data; it does NOT trust HashB64 for security.
func VerifySignedEventPayload(e *SignedEvent) error {
	if e == nil {
		return fmt.Errorf("nil event")
	}
	if e.ID == "" {
		return fmt.Errorf("missing id")
	}
	if len(e.Data) == 0 {
		return fmt.Errorf("missing data")
	}
	if e.SigAlgo == "" || e.SigB64 == "" || e.PubB64 == "" {
		return fmt.Errorf("missing signature fields (sig_algo/sig_b64/pub_b64)")
	}

	pubKey, err := base64.StdEncoding.DecodeString(e.PubB64)
	if err != nil {
		return fmt.Errorf("invalid pub_b64: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(e.SigB64)
	if err != nil {
		return fmt.Errorf("invalid sig_b64: %w", err)
	}

	// Canonicalize data ONLY then hash
	canon, err := jsoncanonicalizer.Transform([]byte(e.Data))
	if err != nil {
		return fmt.Errorf("canonicalization failed: %w", err)
	}
	h := sha256.Sum256(canon)

	// Optional debug consistency check against provided hash_b64
	if e.HashB64 != "" {
		wantHash, err := base64.StdEncoding.DecodeString(e.HashB64)
		if err != nil {
			return fmt.Errorf("invalid hash_b64: %w", err)
		}
		if len(wantHash) != 32 {
			return fmt.Errorf("hash_b64 must decode to 32 bytes, got %d", len(wantHash))
		}
		if !bytes.Equal(wantHash, h[:]) {
			return fmt.Errorf("hash_b64 mismatch (payload vs recomputed)")
		}
	}

	s := oqs.Signature{}
	defer s.Clean()

	if err := s.Init(e.SigAlgo, nil); err != nil {
		return fmt.Errorf("oqs init failed: %w", err)
	}
	valid, err := s.Verify(h[:], signature, pubKey)
	if err != nil {
		return fmt.Errorf("verify error: %w", err)
	}
	if !valid {
		return fmt.Errorf("signature invalid")
	}

	return nil
}

/**************** Ledger functions ****************/

// InitLedger can remain empty for your SignedEvent use-case, or you can preload a sample.
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

// CreateSignedEvent stores a new SignedEvent after verification.
func (s *SmartContract) CreateSignedEvent(ctx contractapi.TransactionContextInterface, eventJSON string) error {
	var ev SignedEvent
	if err := json.Unmarshal([]byte(eventJSON), &ev); err != nil {
		return fmt.Errorf("invalid signed event json: %w", err)
	}

	// Verify BEFORE writing
	if err := VerifySignedEventPayload(&ev); err != nil {
		return err
	}

	exists, err := s.SignedEventExists(ctx, ev.ID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the event %s already exists", ev.ID)
	}

	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(ev.ID, b)
}

// ReadSignedEvent returns the SignedEvent stored in the world state with given id.
func (s *SmartContract) ReadSignedEvent(ctx contractapi.TransactionContextInterface, id string) (*SignedEvent, error) {
	evJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if evJSON == nil {
		return nil, fmt.Errorf("the event %s does not exist", id)
	}

	var ev SignedEvent
	if err := json.Unmarshal(evJSON, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// UpdateSignedEvent updates an existing SignedEvent after verification.
func (s *SmartContract) UpdateSignedEvent(ctx contractapi.TransactionContextInterface, eventJSON string) error {
	var ev SignedEvent
	if err := json.Unmarshal([]byte(eventJSON), &ev); err != nil {
		return fmt.Errorf("invalid signed event json: %w", err)
	}

	// Verify BEFORE writing
	if err := VerifySignedEventPayload(&ev); err != nil {
		return err
	}

	exists, err := s.SignedEventExists(ctx, ev.ID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the event %s does not exist", ev.ID)
	}

	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(ev.ID, b)
}

// DeleteSignedEvent deletes a SignedEvent from the world state.
func (s *SmartContract) DeleteSignedEvent(ctx contractapi.TransactionContextInterface, id string) error {
	exists, err := s.SignedEventExists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the event %s does not exist", id)
	}
	return ctx.GetStub().DelState(id)
}

// SignedEventExists returns true when event with given ID exists in world state.
func (s *SmartContract) SignedEventExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	evJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return evJSON != nil, nil
}

// VerifyEventOnLedger verifies a stored event again (useful for audits/tests).
func (s *SmartContract) VerifyEventOnLedger(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	ev, err := s.ReadSignedEvent(ctx, id)
	if err != nil {
		return false, err
	}
	if err := VerifySignedEventPayload(ev); err != nil {
		return false, err
	}
	return true, nil
}

// GetAllSignedEvents returns all SignedEvents found in world state.
func (s *SmartContract) GetAllSignedEvents(ctx contractapi.TransactionContextInterface) ([]*SignedEvent, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var events []*SignedEvent
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var ev SignedEvent
		if err := json.Unmarshal(queryResponse.Value, &ev); err != nil {
			return nil, err
		}
		events = append(events, &ev)
	}
	return events, nil
}
