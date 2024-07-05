package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid body"))
		return
	}

	err = protojson.Unmarshal(body, &submittedSignature)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid submittedSignature json"))
		return
	}

	if time.Now().UnixMilli() > submittedSignature.Expiration {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Expired signature"))
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

	_, found := api.validators[signer]
	if !found {
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

		recipient, err := base58.Decode(submittedSignature.Transaction.Recipient)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid recipient"))
			return
		}

		relayer, err := base58.Decode(submittedSignature.Transaction.Relayer)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid relayer"))
			return
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

		// check signatures
		for index, signature := range submittedSignature.Transaction.Signatures {
			validatorReceived := submittedSignature.Transaction.Validators[index]

			_, found := api.validators[validatorReceived]
			if !found {
				errMsg := fmt.Sprintf("validator %s is not allowed", validatorReceived)
				log.Errorf(errMsg)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(errMsg))
				return
			}

			validatorCalculated, err := util.RecoverKoinosAddressFromSignature(signature, hash[:])
			if err != nil {
				log.Error(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("cannot recover validator address"))
				return
			}

			if validatorReceived != validatorCalculated {
				errMsg := fmt.Sprintf("the signature provided for validator %s does not match the address recovered %s", validatorReceived, validatorCalculated)
				log.Errorf(errMsg)
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(errMsg))
				return
			}
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
			if ethTx.Status == bridge_pb.TransactionStatus_completed {
				for index, validatr := range ethTx.Validators {
					if validatr == api.koinosAddress {
						response = ethTx.Signatures[index]
					}
				}
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

			signatures := make(map[string]string)

			for index, validatr := range ethTx.Validators {
				signatures[validatr] = ethTx.Signatures[index]

				if validatr == api.koinosAddress {
					response = ethTx.Signatures[index]
				}
			}

			for index, validatr := range submittedSignature.Transaction.Validators {
				_, found := signatures[validatr]
				if !found {
					signatures[validatr] = submittedSignature.Transaction.Signatures[index]
				}
			}

			ethTx.Validators = []string{}
			ethTx.Signatures = []string{}
			for val, sig := range signatures {
				ethTx.Validators = append(ethTx.Validators, val)
				ethTx.Signatures = append(ethTx.Signatures, sig)
			}
		} else {
			ethTx = submittedSignature.Transaction
		}

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

			// check signatures
			for index, signature := range submittedSignature.Transaction.Signatures {
				validatorReceived := submittedSignature.Transaction.Validators[index]

				_, found := api.validators[validatorReceived]
				if !found {
					errMsg := fmt.Sprintf("validator %s is not allowed", validatorReceived)
					log.Errorf(errMsg)
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(errMsg))
					return
				}

				recoveredAddr, err := util.RecoverEthereumAddressFromSignature(signature, prefixedHash.Bytes())

				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("cannot recover validator address"))
					return
				}

				if validatorReceived != recoveredAddr {
					errMsg := fmt.Sprintf("the signature provided for validator %s does not match the address recovered %s", validatorReceived, recoveredAddr)
					log.Errorf(errMsg)
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(errMsg))
					return
				}
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
				if koinosTx.Status == bridge_pb.TransactionStatus_completed {
					for index, validatr := range koinosTx.Validators {
						if validatr == api.ethAddress {
							response = koinosTx.Signatures[index]
						}
					}
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

				signatures := make(map[string]string)

				for index, validatr := range koinosTx.Validators {
					signatures[validatr] = koinosTx.Signatures[index]

					if validatr == api.ethAddress {
						response = koinosTx.Signatures[index]
					}
				}

				for index, validatr := range submittedSignature.Transaction.Validators {
					_, found := signatures[validatr]
					if !found {
						signatures[validatr] = submittedSignature.Transaction.Signatures[index]
					}
				}

				koinosTx.Validators = []string{}
				koinosTx.Signatures = []string{}
				for val, sig := range signatures {
					koinosTx.Validators = append(koinosTx.Validators, val)
					koinosTx.Signatures = append(koinosTx.Signatures, sig)
				}
			} else {
				koinosTx = submittedSignature.Transaction
			}

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
