package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/dgraph-io/badger/v3"

	koinosmq "github.com/koinos/koinos-mq-golang"

	"github.com/roaminroe/koinos-bridge-validator/internal/ethereum"
	"github.com/roaminroe/koinos-bridge-validator/internal/rpc"
	"github.com/roaminroe/koinos-bridge-validator/internal/store"
	"github.com/roaminroe/koinos-bridge-validator/internal/util"
	"github.com/roaminroe/koinos-bridge-validator/proto/build/github.com/roaminroe/koinos-bridge-validator/bridge_pb"

	log "github.com/koinos/koinos-log-golang"
	koinosUtil "github.com/koinos/koinos-util-golang"

	flag "github.com/spf13/pflag"
)

const (
	basedirOption    = "basedir"
	amqpOption       = "amqp"
	instanceIDOption = "instance-id"
	logLevelOption   = "log-level"
	resetOption      = "reset"
	noP2POption      = "no-p2p"

	ethRPCOption               = "eth-rpc"
	ethContractOption          = "eth-contract"
	ethLogsTopicOption         = "eth-logs-topic"
	ethBlockStartOption        = "eth-block-start"
	ethPKOption                = "eth-pk"
	ethMaxBlocksToStreamOption = "eth-max-blocks-stream"

	koinosContractOption          = "koinos-contract"
	koinosBlockStartOption        = "koinos-block-start"
	koinosPKOption                = "koinos-pk"
	koinosMaxBlocksToStreamOption = "koinos-max-blocks-stream"

	validatorsOption      = "validators"
	tokensAddressesOption = "token-addresses"
)

const (
	basedirDefault    = ".koinos-bridge"
	amqpDefault       = "amqp://guest:guest@localhost:5672/"
	instanceIDDefault = ""
	logLevelDefault   = "info"
	resetDefault      = false
	noP2PDefault      = false

	ethRPCDefault               = "http://127.0.0.1:8545/"
	ethBlockStartDefault        = "0"
	ethMaxBlocksToStreamDefault = "1000"

	koinosBlockStartDefault        = "0"
	koinosMaxBlocksToStreamDefault = "1000"

	emptyDefault = ""
)

const (
	pluginName = "plugin.bridge"
	appName    = "koinos_bridge"
	logDir     = "logs"
)

func main() {
	var baseDir = flag.StringP(basedirOption, "d", basedirDefault, "the base directory")
	var amqp = flag.StringP(amqpOption, "a", amqpDefault, "AMQP server URL")
	var reset = flag.BoolP(resetOption, "r", resetDefault, "reset the database")
	var noP2P = flag.BoolP(noP2POption, "b", noP2PDefault, "disable P2P")
	instanceID := flag.StringP(instanceIDOption, "i", instanceIDDefault, "The instance ID to identify this service")
	logLevel := flag.StringP(logLevelOption, "l", logLevelDefault, "The log filtering level (debug, info, warn, error)")

	ethRPC := flag.StringP(ethRPCOption, "e", ethRPCDefault, "The url of the Ethereum RPC")
	ethContract := flag.StringP(ethContractOption, "c", emptyDefault, "The address of the Ethereum bridge contract")
	ethLogsTopic := flag.StringP(ethLogsTopicOption, "n", emptyDefault, "The topic to use when strea;ing the Ethereum contract logs")
	ethBlockStart := flag.StringP(ethBlockStartOption, "t", ethBlockStartDefault, "The block from where to start the Ethereum blockchain streaming")
	ethPK := flag.StringP(ethPKOption, "p", emptyDefault, "The private key to use to sign Ethereum related transfers")
	ethMaxBlocksToStream := flag.StringP(ethMaxBlocksToStreamOption, "f", ethMaxBlocksToStreamDefault, "The maximum number of blocks to retrieve during Ethereum blockchain streaming")

	koinosContract := flag.StringP(koinosContractOption, "k", emptyDefault, "The address of the Koinos bridge contract")
	koinosBlockStart := flag.StringP(koinosBlockStartOption, "o", koinosBlockStartDefault, "The block from where to start the Koinos blockchain streaming")
	koinosPK := flag.StringP(koinosPKOption, "w", emptyDefault, "The private key to use to sign Koinos related transfers")
	koinosMaxBlocksToStream := flag.StringP(koinosMaxBlocksToStreamOption, "g", koinosMaxBlocksToStreamDefault, "The maximum number of blocks to retrieve during Koinos blockchain streaming")

	validators := flag.StringSliceP(validatorsOption, "v", []string{}, "Koinos Addresses of the validators")
	tokenAddressesArr := flag.StringSliceP(tokensAddressesOption, "s", []string{}, "Addresses of the tokens supported by the bridge in the foram KOIN_TOKEN_ADDRRESS1:ETH_TOKEN_ADDRRESS1")

	flag.Parse()

	var err error
	*baseDir = koinosUtil.InitBaseDir(*baseDir)
	if err != nil {
		panic(fmt.Sprintf("Could not initialize baseDir: %s", *baseDir))
	}

	yamlConfig := util.InitYamlConfig(*baseDir)

	*amqp = koinosUtil.GetStringOption(amqpOption, amqpDefault, *amqp, yamlConfig.KoinosBridge, yamlConfig.Global)
	*logLevel = koinosUtil.GetStringOption(logLevelOption, logLevelDefault, *logLevel, yamlConfig.KoinosBridge, yamlConfig.Global)
	*instanceID = koinosUtil.GetStringOption(instanceIDOption, koinosUtil.GenerateBase58ID(5), *instanceID, yamlConfig.KoinosBridge, yamlConfig.Global)
	*reset = koinosUtil.GetBoolOption(resetOption, resetDefault, *reset, yamlConfig.KoinosBridge, yamlConfig.Global)
	*noP2P = koinosUtil.GetBoolOption(noP2POption, noP2PDefault, *noP2P, yamlConfig.KoinosBridge, yamlConfig.Global)

	*ethRPC = koinosUtil.GetStringOption(ethRPCOption, ethRPCDefault, *ethRPC, yamlConfig.KoinosBridge, yamlConfig.Global)
	*ethContract = koinosUtil.GetStringOption(ethContractOption, emptyDefault, *ethContract, yamlConfig.KoinosBridge, yamlConfig.Global)
	*ethLogsTopic = koinosUtil.GetStringOption(*ethLogsTopic, emptyDefault, *ethLogsTopic, yamlConfig.KoinosBridge, yamlConfig.Global)
	*ethBlockStart = koinosUtil.GetStringOption(ethBlockStartOption, ethBlockStartDefault, *ethBlockStart, yamlConfig.KoinosBridge, yamlConfig.Global)
	*ethPK = koinosUtil.GetStringOption(ethPKOption, emptyDefault, *ethPK, yamlConfig.KoinosBridge, yamlConfig.Global)
	*ethMaxBlocksToStream = koinosUtil.GetStringOption(ethMaxBlocksToStreamOption, ethMaxBlocksToStreamDefault, *ethMaxBlocksToStream, yamlConfig.KoinosBridge, yamlConfig.Global)

	*koinosContract = koinosUtil.GetStringOption(koinosContractOption, emptyDefault, *koinosContract, yamlConfig.KoinosBridge, yamlConfig.Global)
	*koinosBlockStart = koinosUtil.GetStringOption(koinosBlockStartOption, emptyDefault, *koinosBlockStart, yamlConfig.KoinosBridge, yamlConfig.Global)
	*koinosPK = koinosUtil.GetStringOption(koinosPKOption, emptyDefault, *koinosPK, yamlConfig.KoinosBridge, yamlConfig.Global)
	*koinosMaxBlocksToStream = koinosUtil.GetStringOption(koinosMaxBlocksToStreamOption, koinosMaxBlocksToStreamDefault, *koinosMaxBlocksToStream, yamlConfig.KoinosBridge, yamlConfig.Global)

	*validators = koinosUtil.GetStringSliceOption(validatorsOption, *validators, yamlConfig.KoinosBridge, yamlConfig.Global)
	*tokenAddressesArr = koinosUtil.GetStringSliceOption(tokensAddressesOption, *tokenAddressesArr, yamlConfig.KoinosBridge, yamlConfig.Global)

	tokenAddresses := make(map[string]string)

	for _, tokensStr := range *tokenAddressesArr {
		// first element is Koin token address
		// second element is Ethereum token address
		tokens := strings.Split(tokensStr, ":")

		tokenAddresses[tokens[0]] = tokens[1]
		tokenAddresses[tokens[1]] = tokens[0]
	}

	appID := fmt.Sprintf("%s.%s", appName, *instanceID)

	// Initialize logger
	logFilename := path.Join(koinosUtil.GetAppDir(*baseDir, appName), logDir, appName+".log")
	err = log.InitLogger(*logLevel, false, logFilename, appID)
	if err != nil {
		panic(fmt.Sprintf("Invalid log-level: %s. Please choose one of: debug, info, warn, error", *logLevel))
	}

	// metadata store
	metadataDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "metadata")
	koinosUtil.EnsureDir(metadataDbDir)
	log.Infof("Opening database at %s", metadataDbDir)

	var metadataDbOpts = badger.DefaultOptions(metadataDbDir)
	metadataDbOpts.Logger = store.KoinosBadgerLogger{}
	var metadataDbBackend = store.NewBadgerBackend(metadataDbOpts)
	defer metadataDbBackend.Close()

	metadataStore := store.NewMetadataStore(metadataDbBackend)

	// koinos transactions store
	koinosDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "koinos_transactions")
	koinosUtil.EnsureDir(koinosDbDir)
	log.Infof("Opening database at %s", koinosDbDir)

	var koinosDbOpts = badger.DefaultOptions(koinosDbDir)
	koinosDbOpts.Logger = store.KoinosBadgerLogger{}
	var koinosDbBackend = store.NewBadgerBackend(koinosDbOpts)
	defer koinosDbBackend.Close()

	// koinosTxStore := store.NewTransactionsStore(koinosDbBackend)

	// ethereum transactions store
	ethDbDir := path.Join(koinosUtil.GetAppDir((*baseDir), appName), "ethereum_transactions")
	koinosUtil.EnsureDir(ethDbDir)
	log.Infof("Opening database at %s", ethDbDir)

	var ethDbOpts = badger.DefaultOptions(ethDbDir)
	ethDbOpts.Logger = store.KoinosBadgerLogger{}
	var ethDbBackend = store.NewBadgerBackend(ethDbOpts)
	defer ethDbBackend.Close()

	ethTxStore := store.NewTransactionsStore(ethDbBackend)

	// Reset backend if requested
	if *reset {
		log.Info("Resetting database")
		err := metadataDbBackend.Reset()
		if err != nil {
			panic(fmt.Sprintf("Error resetting metadata database: %s\n", err.Error()))
		}

		ethDbBackend.Reset()
		if err != nil {
			panic(fmt.Sprintf("Error resetting ethereum transactions database: %s\n", err.Error()))
		}

		koinosDbBackend.Reset()
		if err != nil {
			panic(fmt.Sprintf("Error resetting koinos transactions database: %s\n", err.Error()))
		}
	}

	// get metadata
	metadata, err := metadataStore.Get()

	if err != nil {
		panic(err)
	}

	if metadata == nil {
		metadata = &bridge_pb.Metadata{
			LastEthereumBlockParsed: *ethBlockStart,
		}
		metadataStore.Put(metadata)
	}

	log.Infof("LastEthereumBlockParsed %s", metadata.LastEthereumBlockParsed)

	// AMQP init
	client := koinosmq.NewClient(*amqp, koinosmq.ExponentialBackoff)
	requestHandler := koinosmq.NewRequestHandler(*amqp)

	client.Start()

	log.Infof("starting listening amqp server %s\n", *amqp)

	requestHandler.SetRPCHandler(pluginName, rpc.HandleRPC)

	requestHandler.Start()

	log.Info("request handler started")

	if !*noP2P {
		log.Info("Attempting to connect to p2p...")
		for {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			val, _ := rpc.IsConnectedToP2P(ctx, client)
			if val {
				log.Info("Connected to P2P")
				break
			}
		}
	}

	// blockchains streaming

	ctx, cancel := context.WithCancel(context.Background())

	if *ethRPC != "none" {
		go ethereum.StreamEthereumBlocks(
			ctx,
			client,
			metadataStore,
			metadata.LastEthereumBlockParsed,
			*ethRPC,
			*ethContract,
			*ethLogsTopic,
			*ethMaxBlocksToStream,
			*noP2P,
			*koinosPK,
			*koinosContract,
			tokenAddresses,
			ethTxStore,
		)
	}

	// Wait for a SIGINT or SIGTERM signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Info("closing service gracefully")
	cancel()
	log.Info("graceful stop completed")
}
