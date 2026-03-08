package main

import (
	"log"

	"github.com/Mr-J486/QuantumShield/pqcCC_demo/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func main() {
	assetChaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating pqcCC chaincode: %v", err)
	}

	if err := assetChaincode.Start(); err != nil {
		log.Panicf("Error starting pqcCC chaincode: %v", err)
	}
}
