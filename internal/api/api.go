package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/koinos/koinos-log-golang"
	"github.com/mr-tron/base58"

	"net/http"

	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/proto/build/github.com/koinos-bridge/koinos-bridge-validator/bridge_pb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Api struct {
	ethTxStore            *store.TransactionsStore
	koinosTxStore         *store.TransactionsStore
	koinosContractAddress []byte
	ethContractAddress    common.Address
	validators            map[string]util.ValidatorConfig
	koinosAddress         string
	ethAddress            string
}

func NewApi(ethTxStore *store.TransactionsStore, koinosTxStore *store.TransactionsStore, koinosContractStr string, ethContractStr string, validators map[string]util.ValidatorConfig, koinosAddress string, ethAddress string) *Api {
	ethContractAddress := common.HexToAddress(ethContractStr)

	koinosContractAddress, err := base58.Decode(koinosContractStr)
	if err != nil {
		log.Error(err.Error())
		panic(err)
	}

	if common.IsHexAddress(ethAddress) {
		ethAddress = common.HexToAddress(ethAddress).Hex()
	}

	return &Api{
		ethTxStore:            ethTxStore,
		koinosTxStore:         koinosTxStore,
		koinosContractAddress: koinosContractAddress,
		ethContractAddress:    ethContractAddress,
		validators:            validators,
		koinosAddress:         koinosAddress,
		ethAddress:            ethAddress,
	}
}

func (api *Api) GetEthereumTransaction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // cors
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
		return
	}

	transactionIdParams := r.URL.Query()["TransactionId"]

	if len(transactionIdParams) <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing TransactionId param"))
		return
	}

	transaction, _ := api.ethTxStore.Get(transactionIdParams[0])

	if transaction == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("transaction does not exist"))
		return
	}

	m := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}

	jsonBytes, err := m.Marshal(transaction)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("unknown error"))
		log.Error(err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func (api *Api) GetKoinosTransaction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // cors
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
		return
	}

	transactionIdParams := r.URL.Query()["TransactionId"]
	opIdParams := r.URL.Query()["OpId"]

	if len(transactionIdParams) <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing TransactionId param"))
		return
	}

	// if no other bridge unrelated operations are present in the transaction
	// the opId is 1 or 3
	opId := "1"

	if len(opIdParams) > 0 {
		opId = opIdParams[0]
	}

	txKey := transactionIdParams[0] + "-" + opId

	transaction, _ := api.koinosTxStore.Get(txKey)

	if transaction == nil {
		if opId == "1" {
			opId = "3"
			txKey = transactionIdParams[0] + "-" + opId
			transaction, _ = api.koinosTxStore.Get(txKey)
			if transaction == nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("transaction does not exist"))
				return
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("transaction does not exist"))
			return
		}
	}

	m := protojson.MarshalOptions{
		EmitUnpopulated: true,
	}

	jsonBytes, err := m.Marshal(transaction)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("unknown error"))
		log.Error(err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func (api *Api) SubmitSignature(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
		return
	}

	var submittedSignature bridge_pb.SubmittedSignature
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, (1<<20)+1))

	if err != nil || len(body) > 1<<20 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid or oversized body"))
		return
	}

	err = protojson.Unmarshal(body, &submittedSignature)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid submittedSignature json"))
		return
	}

	now := time.Now().UnixMilli()
	tx := submittedSignature.Transaction
	if tx == nil || (tx.Type != bridge_pb.TransactionType_ethereum && tx.Type != bridge_pb.TransactionType_koinos) || tx.Expiration <= uint64(now) {
		http.Error(w, "Missing, unknown or expired transfer", http.StatusBadRequest)
		return
	}
	for _, value := range []string{tx.Amount, tx.Payment} {
		if _, err := strconv.ParseUint(value, 0, 64); err != nil {
			http.Error(w, "Invalid transfer amount or payment", http.StatusBadRequest)
			return
		}
	}
	if _, err := strconv.ParseUint(tx.ToChain, 0, 32); err != nil {
		http.Error(w, "Invalid transfer chain", http.StatusBadRequest)
		return
	}
	if now >= submittedSignature.Expiration || submittedSignature.Expiration > now+120000 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid signature expiry"))
		return
	}

	expirationBytes := []byte(strconv.FormatInt(submittedSignature.Expiration, 10))

	transactionBytes, err := proto.Marshal(submittedSignature.Transaction)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid transactionBytes"))
		return
	}

	bytesToHash := append(transactionBytes, expirationBytes...)

	hash := sha256.Sum256(bytesToHash)

	signer, err := util.RecoverKoinosAddressFromSignature(submittedSignature.Signature, hash[:])
	if err != nil {
		log.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("cannot recover signer address"))
		return
	}

	authorized := false
	for _, validator := range api.validators {
		if validator.KoinosAddress == signer {
			authorized = true
		}
	}
	if !authorized {
		errMsg := fmt.Sprintf("signer %s is not allowed", signer)
		log.Errorf(errMsg)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(errMsg))
		return
	}

	if submittedSignature.Transaction.Type == bridge_pb.TransactionType_ethereum {
		log.Debugf("received Ethereum tx %s / validators: %+q / signatures: %+q", submittedSignature.Transaction.Id, submittedSignature.Transaction.Validators, submittedSignature.Transaction.Signatures)
		// check transaction hash
		txIdBytes := common.FromHex(submittedSignature.Transaction.Id)

		amount, err := strconv.ParseUint(submittedSignature.Transaction.Amount, 0, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid amount"))
			return
		}

		payment, err := strconv.ParseUint(submittedSignature.Transaction.Payment, 0, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid payment"))
			return
		}

		chain64, err := strconv.ParseUint(submittedSignature.Transaction.ToChain, 0, 32)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid chain"))
			return
		}

		if chain64 > uint64(^uint32(0)) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid overflow"))
			return
		}

		chain := uint32(chain64)

		koinosToken, err := base58.Decode(submittedSignature.Transaction.KoinosToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid koinosToken"))
			return
		}

		recipient := []byte("")
		if submittedSignature.Transaction.Recipient != "" {
			recipient, err = base58.Decode(submittedSignature.Transaction.Recipient)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid recipient"))
				return
			}
		}

		relayer := []byte("")
		if submittedSignature.Transaction.Relayer != "" {
			relayer, err = base58.Decode(submittedSignature.Transaction.Relayer)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid relayer"))
				return
			}
		}

		completeTransferHash := &bridge_pb.CompleteTransferHash{
			Action:        bridge_pb.ActionId_complete_transfer,
			TransactionId: txIdBytes,
			Token:         koinosToken,
			Recipient:     recipient,
			Relayer:       relayer,
			Amount:        amount,
			Payment:       payment,
			ContractId:    api.koinosContractAddress,
			Metadata:      submittedSignature.Transaction.Metadata,
			Expiration:    submittedSignature.Transaction.Expiration,
			Chain:         chain,
		}

		completeTransferHashBytes, err := proto.Marshal(completeTransferHash)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid completeTransferHash"))
			return
		}

		hash := sha256.Sum256(completeTransferHashBytes)
		hashB64 := base64.URLEncoding.EncodeToString(hash[:])

		if hashB64 != submittedSignature.Transaction.Hash {
			errMsg := fmt.Sprintf("the calulated hash for tx %s is different than the one received %s != calculated %s", submittedSignature.Transaction.Id, submittedSignature.Transaction.Hash, hashB64)
			log.Errorf(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(errMsg))
			return
		}

		if len(submittedSignature.Transaction.Validators) != len(submittedSignature.Transaction.Signatures) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("mismatch number validators and signatures"))
			return
		}

		incomingSignatures, err := util.VerifyTransferSignatures(submittedSignature.Transaction, api.validators)
		if err != nil {
			http.Error(w, "Invalid, duplicate or unconfigured transfer signatures", http.StatusBadRequest)
			return
		}

		// check if we already have this transaction in our store
		api.ethTxStore.Lock()
		ethTx, err := api.ethTxStore.Get(submittedSignature.Transaction.Id)
		if err != nil {
			log.Errorf(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("error while getting transaction"))
			api.ethTxStore.Unlock()
			return
		}

		response := ""

		if ethTx != nil {
			storedSignatures, verifyErr := util.VerifyTransferSignatures(ethTx, api.validators)
			if verifyErr != nil {
				api.ethTxStore.Unlock()
				http.Error(w, "Stored signature evidence requires local recovery", http.StatusConflict)
				return
			}
			if ethTx.Status == bridge_pb.TransactionStatus_completed {
				response = storedSignatures[api.koinosAddress]
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(response))
				api.ethTxStore.Unlock()
				return
			}

			if ethTx.Hash != hashB64 {
				errMsg := fmt.Sprintf("the calculated hash for tx %s is different than the one received %s != calculated %s", submittedSignature.Transaction.Hash, ethTx.Hash, hashB64)

				log.Errorf(errMsg)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(errMsg))
				api.ethTxStore.Unlock()
				return
			}

			signatures := storedSignatures
			response = signatures[api.koinosAddress]
			for val, sig := range incomingSignatures {
				if _, found := signatures[val]; !found {
					signatures[val] = sig
				}
			}
			ethTx.Validators = nil
			ethTx.Signatures = nil
			for val, sig := range signatures {
				ethTx.Validators = append(ethTx.Validators, val)
				ethTx.Signatures = append(ethTx.Signatures, sig)
			}
		} else {
			ethTx = proto.Clone(submittedSignature.Transaction).(*bridge_pb.Transaction)
			ethTx.Validators = nil
			ethTx.Signatures = nil
			for val, sig := range incomingSignatures {
				ethTx.Validators = append(ethTx.Validators, val)
				ethTx.Signatures = append(ethTx.Signatures, sig)
			}
		}
		ethTx.CompletionTransactionId = ""
		ethTx.Status = bridge_pb.TransactionStatus_gathering_signatures

		if len(ethTx.Signatures) >= ((((len(api.validators)/2)*10)/3)*2)/10+1 {
			ethTx.Status = bridge_pb.TransactionStatus_signed
		}

		err = api.ethTxStore.Put(ethTx.Id, ethTx)
		api.ethTxStore.Unlock()

		if err != nil {
			log.Errorf(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("error while saving transaction"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
		return
	}

	if submittedSignature.Transaction.Type == bridge_pb.TransactionType_koinos {
		log.Debugf("received Koinos tx %s / validators: %+q / signatures: %+q", submittedSignature.Transaction.Id, submittedSignature.Transaction.Validators, submittedSignature.Transaction.Signatures)
		// check transaction hash
		txIdBytes := common.FromHex(submittedSignature.Transaction.Id)

		amount := submittedSignature.Transaction.Amount
		payment := submittedSignature.Transaction.Payment

		ethToken := common.FromHex(submittedSignature.Transaction.EthToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid ethToken"))
			return
		}

		recipient := common.FromHex(submittedSignature.Transaction.Recipient)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid recipient"))
			return
		}

		relayer := common.FromHex(submittedSignature.Transaction.Relayer)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid relayer"))
			return
		}

		chainId, err := strconv.ParseUint(submittedSignature.Transaction.ToChain, 0, 64)
		if err != nil {
			log.Errorf(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		operationId, err := strconv.ParseUint(submittedSignature.Transaction.OpId, 0, 64)
		if err != nil {
			log.Errorf(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		} else {
			_, prefixedHash := util.GenerateEthereumCompleteTransferHash(txIdBytes, operationId, ethToken, recipient, relayer, payment, amount, api.ethContractAddress, submittedSignature.Transaction.Metadata, submittedSignature.Transaction.Expiration, chainId)

			if prefixedHash.Hex() != submittedSignature.Transaction.Hash {
				errMsg := fmt.Sprintf("the calulated hash for tx %s is different than the one received %s != calculated %s", submittedSignature.Transaction.Id, submittedSignature.Transaction.Hash, prefixedHash.Hex())
				log.Errorf(errMsg)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(errMsg))
				return
			}

			if len(submittedSignature.Transaction.Validators) != len(submittedSignature.Transaction.Signatures) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("mismatch number validators and signatures"))
				return
			}

			incomingSignatures, err := util.VerifyTransferSignatures(submittedSignature.Transaction, api.validators)
			if err != nil {
				http.Error(w, "Invalid, duplicate or unconfigured transfer signatures", http.StatusBadRequest)
				return
			}

			// check if we already have this transaction in our store
			txKey := submittedSignature.Transaction.Id + "-" + submittedSignature.Transaction.OpId
			api.koinosTxStore.Lock()
			koinosTx, err := api.koinosTxStore.Get(txKey)
			if err != nil {
				log.Errorf(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("error while getting transaction"))
				api.koinosTxStore.Unlock()
				return
			}

			response := ""

			if koinosTx != nil {
				storedSignatures, verifyErr := util.VerifyTransferSignatures(koinosTx, api.validators)
				if verifyErr != nil {
					api.koinosTxStore.Unlock()
					http.Error(w, "Stored signature evidence requires local recovery", http.StatusConflict)
					return
				}
				if koinosTx.Status == bridge_pb.TransactionStatus_completed {
					response = storedSignatures[api.ethAddress]
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(response))
					api.koinosTxStore.Unlock()
					return
				}

				if koinosTx.Hash != prefixedHash.Hex() {
					errMsg := fmt.Sprintf("the calculated hash for tx %s is different than the one received %s != calculated %s", submittedSignature.Transaction.Hash, koinosTx.Hash, prefixedHash.Hex())

					log.Errorf(errMsg)
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(errMsg))
					api.koinosTxStore.Unlock()
					return
				}

				signatures := storedSignatures
				response = signatures[api.ethAddress]
				for val, sig := range incomingSignatures {
					if _, found := signatures[val]; !found {
						signatures[val] = sig
					}
				}
				koinosTx.Validators = nil
				koinosTx.Signatures = nil
				for val, sig := range signatures {
					koinosTx.Validators = append(koinosTx.Validators, val)
					koinosTx.Signatures = append(koinosTx.Signatures, sig)
				}
			} else {
				koinosTx = proto.Clone(submittedSignature.Transaction).(*bridge_pb.Transaction)
				koinosTx.Validators = nil
				koinosTx.Signatures = nil
				for val, sig := range incomingSignatures {
					koinosTx.Validators = append(koinosTx.Validators, val)
					koinosTx.Signatures = append(koinosTx.Signatures, sig)
				}
			}
			koinosTx.CompletionTransactionId = ""
			koinosTx.Status = bridge_pb.TransactionStatus_gathering_signatures

			if len(koinosTx.Signatures) >= ((((len(api.validators)/2)*10)/3)*2)/10+1 {
				koinosTx.Status = bridge_pb.TransactionStatus_signed
			}

			err = api.koinosTxStore.Put(txKey, koinosTx)
			api.koinosTxStore.Unlock()

			if err != nil {
				log.Errorf(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("error while saving transaction"))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(response))
			return
		}
	}
}
