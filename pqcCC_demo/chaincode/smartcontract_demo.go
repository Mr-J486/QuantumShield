package chaincode

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

// Your asset IS the SignedEvent envelope
type SignedEvent struct {
	Data      json.RawMessage `json:"data"`      // original JSON payload (as-is)
	HashAlgo  string          `json:"hash_algo"` // optional/audit
	HashB64   string          `json:"hash_b64"`  // optional/audit (chaincode recomputes anyway)
	SigAlgo   string          `json:"sig_algo"`  // ML-DSA-65
	SigB64    string          `json:"sig_b64"`   // signature over SHA-256(JCS(data))
	PubKeyB64 string          `json:"pub_b64"`   // for testing
}

// Minimal struct to extract event_id from SignedEvent.Data
type eventIDOnly struct {
	EventID string `json:"event_id"`
}

// --------------------
// Create / Update (verified)
// --------------------

// CreateEvent verifies the SignedEvent then stores the whole SignedEvent under key=data.event_id.
func (s *SmartContract) CreateEvent(ctx contractapi.TransactionContextInterface, signedEventJSON string) error {
	key, canonicalSignedJSON, err := verifyAndNormalizeSignedEvent(signedEventJSON)
	if err != nil {
		return err
	}

	exists, err := s.EventExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("event %s already exists", key)
	}

	return ctx.GetStub().PutState(key, canonicalSignedJSON)
}

// UpdateEvent verifies the SignedEvent then overwrites the stored value under key=data.event_id.
func (s *SmartContract) UpdateEvent(ctx contractapi.TransactionContextInterface, signedEventJSON string) error {
	key, canonicalSignedJSON, err := verifyAndNormalizeSignedEvent(signedEventJSON)
	if err != nil {
		return err
	}

	exists, err := s.EventExists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("event %s does not exist", key)
	}

	return ctx.GetStub().PutState(key, canonicalSignedJSON)
}

// --------------------
// Basic read helpers
// --------------------

func (s *SmartContract) ReadEvent(ctx contractapi.TransactionContextInterface, eventID string) (string, error) {
	b, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if b == nil {
		return "", fmt.Errorf("event %s does not exist", eventID)
	}
	return string(b), nil
}

func (s *SmartContract) DeleteEvent(ctx contractapi.TransactionContextInterface, eventID string) error {
	exists, err := s.EventExists(ctx, eventID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("event %s does not exist", eventID)
	}
	return ctx.GetStub().DelState(eventID)
}

func (s *SmartContract) EventExists(ctx contractapi.TransactionContextInterface, eventID string) (bool, error) {
	b, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return b != nil, nil
}

func (s *SmartContract) GetAllEvents(ctx contractapi.TransactionContextInterface) ([]string, error) {
	it, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var out []string
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		out = append(out, string(kv.Value))
	}
	return out, nil
}

// --------------------
// Internal: verify + normalize
// --------------------

// verifyAndNormalizeSignedEvent:
// 1) parses SignedEvent JSON
// 2) extracts event_id from data
// 3) recomputes SHA-256(JCS(data))
// 4) verifies ML-DSA-65 signature over that hash
// 5) returns (event_id, canonicalSignedEventJSONBytesToStore)
func verifyAndNormalizeSignedEvent(signedEventJSON string) (string, []byte, error) {
	var e SignedEvent
	if err := json.Unmarshal([]byte(signedEventJSON), &e); err != nil {
		return "", nil, fmt.Errorf("invalid SignedEvent JSON: %v", err)
	}

	if len(e.Data) == 0 {
		return "", nil, fmt.Errorf("missing data")
	}
	if e.SigAlgo != "" && e.SigAlgo != "ML-DSA-65" {
		return "", nil, fmt.Errorf("unsupported sig_algo: %s (expected ML-DSA-65)", e.SigAlgo)
	}

	// Extract event_id from data (your payload has it)
	var id eventIDOnly
	if err := json.Unmarshal([]byte(e.Data), &id); err != nil {
		return "", nil, fmt.Errorf("data is not valid JSON: %v", err)
	}
	if id.EventID == "" {
		return "", nil, fmt.Errorf("data.event_id is required")
	}

	// Decode pubkey + signature
	pubBytes, err := base64.StdEncoding.DecodeString(e.PubKeyB64)
	if err != nil {
		return "", nil, fmt.Errorf("invalid pub_b64: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(e.SigB64)
	if err != nil {
		return "", nil, fmt.Errorf("invalid sig_b64: %v", err)
	}

	// Canonicalize + hash data (ignore HashB64)
	canonData, err := jcs.Transform([]byte(e.Data))
	if err != nil {
		return "", nil, fmt.Errorf("canonicalization failed: %v", err)
	}
	hash := sha256.Sum256(canonData)

	// Parse CIRCL public key
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pubBytes); err != nil {
		return "", nil, fmt.Errorf("public key parse failed: %v", err)
	}

	// Verify signature over hash
	ctxDomain := []byte("") // must match signer
	if ok := mldsa65.Verify(&pk, hash[:], ctxDomain, sigBytes); !ok {
		return "", nil, fmt.Errorf("signature mismatch")
	}

	// Store a normalized JSON form (optional but nice):
	// - keep Data exactly as provided
	// - keep other fields as provided
	// This ensures UTF-8 JSON is stored (Fabric requirement).
	canonicalSigned, err := json.Marshal(e)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal SignedEvent: %v", err)
	}

	return id.EventID, canonicalSigned, nil
}
