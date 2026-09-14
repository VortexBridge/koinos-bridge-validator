package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/api"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/store"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/streamer"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/util"
	"github.com/koinos-bridge/koinos-bridge-validator/internal/worker"
	"github.com/mr-tron/base58"

	log "github.com/koinos/koinos-log-golang"
	koinosUtil "github.com/koinos/koinos-util-golang"

	flag "github.com/spf13/pflag"
)

const (
	basedirOption = "basedir"
)

const (
	basedirDefault    = "~/.koinos"
	instanceIDDefault = ""
	logLevelDefault   = "info"
	resetDefault      = false

	ethRPCDefault               = "http://127.0.0.1:8545/"
	ethBlockStartDefault        = 0
	ethMaxBlocksToStreamDefault = 500
	ethConfirmationsDefault     = 15
	ethPollingTimeDefault       = 3000

	koinosRPCDefault               = "http://127.0.0.1:8080/"
	koinosBlockStartDefault        = 0
	koinosMaxBlocksToStreamDefault = 500
	koinosPollingTimeDefault       = 3000

	emptyDefault = ""

	signaturesExpirationDefault uint = 60 * 60 * 1000 // 60mins
	apiUrlDefault                    = ":3000"
)

const (
	appName = "bridge"
	logDir  = "logs"
)

func main() {
	baseDir := flag.StringP(basedirOption, "d", basedirDefault, "the base directory")

	observeFlag := flag.Bool("observe-only", false, "observe and store events without loading keys or exchanging signatures")
	flag.Parse()

	// Expand ~ to the home directory (otherwise you wind up with /home/user/~/.koinos)
	if strings.HasPrefix(*baseDir, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("Could not get home directory: %v", err))
		}
		*baseDir = filepath.Join(homeDir, (*baseDir)[1:])
	}

	var err error
	*baseDir, err = koinosUtil.InitBaseDir(*baseDir)
	if err != nil {
		panic(fmt.Sprintf("Could not initialize baseDir: %s", *baseDir))
	}

	yamlConfig := util.InitYamlConfig(*baseDir)

	observeOnly := *observeFlag || yamlConfig.Bridge.ObservationOnly
	controlDir := filepath.Join(*baseDir, "bridge", ".operator")
	lease, err := worker.Acquire(controlDir, "process.lock")
	if err != nil {
		panic(err)
	}
	defer lease.Close()
	_, metadataStatErr := os.Stat(filepath.Join(*baseDir, "bridge", "metadata"))
	if metadataStatErr != nil && !os.IsNotExist(metadataStatErr) {
		panic(metadataStatErr)
	}
	if err := worker.EnsureMode(controlDir, observeOnly, metadataStatErr == nil); err != nil {
		panic(err)
	}

	logLevel := util.GetStringOption(yamlConfig.Bridge.LogLevel, logLevelDefault)
	instanceID := util.GetStringOption(yamlConfig.Bridge.InstanceID, koinosUtil.GenerateBase58ID(5))
	reset := util.GetBoolOption(yamlConfig.Bridge.Reset, resetDefault)
	signaturesExpiration := util.GetUIntOption(yamlConfig.Bridge.SignaturesExpiration, signaturesExpirationDefault)
	apiUrl := util.GetStringOption(yamlConfig.Bridge.ApiUrl, apiUrlDefault)

	ethRPC := util.GetStringOption(yamlConfig.Bridge.EthereumRpc, ethRPCDefault)
	ethContract := util.GetStringOption(yamlConfig.Bridge.EthereumContract, emptyDefault)
	ethBlockStart := util.GetUInt64Option(yamlConfig.Bridge.EthereumBlockStart, ethBlockStartDefault)
	ethMaxBlocksToStream := util.GetUInt64Option(yamlConfig.Bridge.EthereumMaxBlocksStream, ethMaxBlocksToStreamDefault)
	ethConfirmations := util.GetUInt64Option(yamlConfig.Bridge.EthereumConfirmations, ethConfirmationsDefault)
	ethPK := util.GetStringOption(yamlConfig.Bridge.EthereumPK, emptyDefault)
	ethPollingTime := util.GetUIntOption(yamlConfig.Bridge.EthereumPollingTime, ethPollingTimeDefault)

	koinosRPC := util.GetStringOption(yamlConfig.Bridge.KoinosRpc, koinosRPCDefault)
	koinosContract := util.GetStringOption(yamlConfig.Bridge.KoinosContract, emptyDefault)
	koinosBlockStart := util.GetUInt64Option(yamlConfig.Bridge.KoinosBlockStart, koinosBlockStartDefault)
	koinosMaxBlocksToStream := util.GetUInt64Option(yamlConfig.Bridge.KoinosMaxBlocksStream, koinosMaxBlocksToStreamDefault)
	koinosPK := util.GetStringOption(yamlConfig.Bridge.KoinosPK, emptyDefault)
	koinosPollingTime := util.GetUIntOption(yamlConfig.Bridge.KoinosPollingTime, koinosPollingTimeDefault)

	validators := make(map[string]util.ValidatorConfig)
	tokenAddresses := make(map[string]util.TokenConfig)

	for _, validator := range yamlConfig.Bridge.Validators {
		validators[validator.KoinosAddress] = validator
		validators[validator.EthereumAddress] = validator
	}

	for _, tokenAddr := range yamlConfig.Bridge.Tokens {
		tokenAddresses[tokenAddr.KoinosAddress] = tokenAddr
		tokenAddresses[tokenAddr.EthereumAddress] = tokenAddr
	}

	appID := fmt.Sprintf("%s.%s", appName, instanceID)

	// Initialize logger
	logFilename := path.Join(koinosUtil.GetAppDir(*baseDir, appName), logDir, appName+".log")
	err = log.InitLogger(logLevel, false, logFilename, appID)
	if err != nil {
		panic(fmt.Sprintf("Invalid log-level: %s. Please choose one of: debug, info, warn, error", logLevel))
	}

	// Observation mode never decodes keys or opens key files.
	var koinosPKbytes []byte
	var ethPrivateKey *ecdsa.PrivateKey
	var koinosAddress, ethAddress string
	if !observeOnly {
		koinosPK, err = worker.LoadKey(koinosPK, yamlConfig.Bridge.KoinosPKFile, false)
		if err != nil {
			panic(err)
		}
		ethPK, err = worker.LoadKey(ethPK, yamlConfig.Bridge.EthereumPKFile, false)
		if err != nil {
			panic(err)
		}
		koinosPKbytes, err = koinosUtil.DecodeWIF(koinosPK)
		if err != nil {
			panic("invalid Koinos signing key")
		}
		koinosKey, err := koinosUtil.NewKoinosKeysFromBytes(koinosPKbytes)
		if err != nil {
			panic("invalid Koinos signing key")
		}
		koinosAddress = base58.Encode(koinosKey.AddressBytes())
		ethPrivateKey, err = crypto.HexToECDSA(ethPK)
		if err != nil {
			panic("invalid EVM signing key")
		}
		ethAddress = crypto.PubkeyToAddress(ethPrivateKey.PublicKey).Hex()
		// Excludes duplicate keys across local instance directories under this OS user.
		// This cannot fence clones on a different host or another OS account.
		configHome, err := os.UserConfigDir()
		if err != nil {
			panic(err)
		}
		for _, identity := range []string{"evm-" + ethAddress, "koinos-" + koinosAddress} {
			identityLease, err := worker.Acquire(filepath.Join(configHome, "vortex", "signer-locks"), identity+".lock")
			if err != nil {
				panic(err)
			}
			defer identityLease.Close()
		}
	}

	// metadata store
	metadataDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "metadata")
	koinosUtil.EnsureDir(metadataDbDir)
	log.Infof("Opening database at %s", metadataDbDir)

	var metadataDbOpts = badger.DefaultOptions(metadataDbDir).WithSyncWrites(true)
	metadataDbOpts.Logger = store.KoinosBadgerLogger{}
	metadataDbBackend, err := store.NewBadgerBackend(metadataDbOpts)
	if err != nil {
		panic(fmt.Sprintf("cannot open metadata database: %v", err))
	}
	defer metadataDbBackend.Close()

	metadataStore := store.NewMetadataStore(metadataDbBackend)

	// koinos transactions store
	koinosDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "koinos_transactions")
	koinosUtil.EnsureDir(koinosDbDir)
	log.Infof("Opening database at %s", koinosDbDir)

	var koinosDbOpts = badger.DefaultOptions(koinosDbDir).WithSyncWrites(true)
	koinosDbOpts.Logger = store.KoinosBadgerLogger{}
	koinosDbBackend, err := store.NewBadgerBackend(koinosDbOpts)
	if err != nil {
		panic(fmt.Sprintf("cannot open koinos database: %v", err))
	}
	defer koinosDbBackend.Close()

	koinosTxStore := store.NewTransactionsStore(koinosDbBackend)

	// ethereum transactions store
	ethDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "ethereum_transactions")
	koinosUtil.EnsureDir(ethDbDir)
	log.Infof("Opening database at %s", ethDbDir)

	var ethDbOpts = badger.DefaultOptions(ethDbDir).WithSyncWrites(true)
	ethDbOpts.Logger = store.KoinosBadgerLogger{}
	ethDbBackend, err := store.NewBadgerBackend(ethDbOpts)
	if err != nil {
		panic(fmt.Sprintf("cannot open eth database: %v", err))
	}
	defer ethDbBackend.Close()

	ethTxStore := store.NewTransactionsStore(ethDbBackend)

	// Reset backend if requested
	if reset {
		log.Info("Resetting database")
		err := metadataDbBackend.Reset()
		if err != nil {
			log.Error(err.Error())
			panic(fmt.Sprintf("Error resetting metadata database: %s\n", err.Error()))
		}

		err = ethDbBackend.Reset()
		if err != nil {
			log.Error(err.Error())
			panic(fmt.Sprintf("Error resetting ethereum transactions database: %s\n", err.Error()))
		}

		err = koinosDbBackend.Reset()
		if err != nil {
			log.Error(err.Error())
			panic(fmt.Sprintf("Error resetting koinos transactions database: %s\n", err.Error()))
		}
	}

	// get metadata
	metadata, err := metadataStore.Get()

	if err != nil {
		log.Error(err.Error())
		panic(err)
	}

	if ethBlockStart > 0 && metadata.LastEthereumBlockParsed == 0 {
		metadata.LastEthereumBlockParsed = ethBlockStart - 1
	}

	if koinosBlockStart > 0 && metadata.LastKoinosBlockParsed == 0 {
		metadata.LastKoinosBlockParsed = koinosBlockStart - 1
	}

	log.Infof("LastEthereumBlockParsed: %d", metadata.LastEthereumBlockParsed)
	log.Infof("LastKoinosBlockParsed: %d", metadata.LastKoinosBlockParsed)

	if err := metadataStore.Put(metadata); err != nil {
		panic(err)
	}

	// blockchains streaming
	mainCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	monitor := worker.NewMonitor(instanceID, observeOnly, ethAddress, koinosAddress)
	control, err := worker.StartControl(controlDir, monitor, stop)
	if err != nil {
		panic(err)
	}
	defer control.Close()

	var wg sync.WaitGroup

	if ethMaxBlocksToStream > 0 {
		wg.Add(1)
		go streamer.StreamEthereumBlocks(
			&wg,
			mainCtx,
			metadataStore,
			metadata.LastEthereumBlockParsed,
			ethRPC,
			ethContract,
			ethMaxBlocksToStream,
			koinosPKbytes,
			koinosAddress,
			koinosContract,
			tokenAddresses,
			ethTxStore,
			koinosTxStore,
			signaturesExpiration,
			validators,
			ethConfirmations,
			ethPollingTime,
			streamer.Options{ObserveOnly: observeOnly, OnProgress: func(h uint64) { monitor.Progress("evm", h) }, OnProblem: func() { monitor.Problem("evm") }},
		)
	}

	if koinosMaxBlocksToStream > 0 {
		wg.Add(1)
		go streamer.StreamKoinosBlocks(
			&wg,
			mainCtx,
			metadataStore,
			metadata.LastKoinosBlockParsed,
			koinosRPC,
			ethPrivateKey,
			ethAddress,
			ethContract,
			koinosMaxBlocksToStream,
			koinosPKbytes,
			koinosAddress,
			koinosContract,
			tokenAddresses,
			ethTxStore,
			koinosTxStore,
			signaturesExpiration,
			validators,
			koinosPollingTime,
			streamer.Options{ObserveOnly: observeOnly, OnProgress: func(h uint64) { monitor.Progress("koinos", h) }, OnProblem: func() { monitor.Problem("koinos") }},
		)
	}

	// Run API server
	api := api.NewApi(ethTxStore, koinosTxStore, koinosContract, ethContract, validators, koinosAddress, ethAddress)
	mux := http.NewServeMux()
	mux.HandleFunc("/GetEthereumTransaction", api.GetEthereumTransaction)
	mux.HandleFunc("/GetKoinosTransaction", api.GetKoinosTransaction)
	if observeOnly {
		mux.HandleFunc("/SubmitSignature", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "signature exchange is disabled in observation mode", http.StatusForbidden)
		})
	} else {
		mux.HandleFunc("/SubmitSignature", api.SubmitSignature)
	}

	httpServer := &http.Server{
		Addr:              apiUrl,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		Handler:           mux,
		BaseContext:       func(_ net.Listener) context.Context { return mainCtx },
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("starting HTTP server listener at %s", apiUrl)

		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Errorf("HTTP server ListenAndServe: %v", err)
			stop()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-mainCtx.Done()
		log.Info("stopping HTTP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			httpServer.Close()
			log.Errorf("Server forced to shutdown: %s", err.Error())
		}
	}()

	wg.Wait()
	log.Info("graceful stop completed")
}
