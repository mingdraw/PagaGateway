package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mingdraw/PagaGateway/internal/gateway"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return writeHelp(os.Stdout, "")
	}
	if isHelp(args[0]) {
		if len(args) > 2 {
			return errors.New("unexpected positional arguments")
		}
		topic := ""
		if len(args) == 2 {
			topic = args[1]
		}
		return writeHelp(os.Stdout, topic)
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if args[0] == "certificate" {
		if len(args) > 1 && isHelp(args[1]) {
			if len(args) != 2 {
				return errors.New("unexpected positional arguments")
			}
			return writeHelp(os.Stdout, "certificate")
		}
		return certificate(args[1:])
	}
	// Re-exec entry point; the instance identifier is not an authentication token.
	if args[0] == "_background" {
		if len(args) != 6 || (args[1] != "server" && args[1] != "client") {
			return errors.New("invalid background invocation")
		}
		return runBackground(args[1], args[2], args[3], args[4], args[5])
	}
	role := args[0]
	if role != "server" && role != "client" {
		return errors.New("unknown command; use pagagateway help")
	}
	if len(args) > 1 && isHelp(args[1]) {
		if len(args) != 2 {
			return errors.New("unexpected positional arguments")
		}
		return writeHelp(os.Stdout, role)
	}
	action, remaining := "", args[1:]
	if len(remaining) > 0 && !strings.HasPrefix(remaining[0], "-") {
		action, remaining = remaining[0], remaining[1:]
	}
	if action != "" && action != "run" && action != "start" && action != "status" && action != "stop" && action != "restart" && action != "clients" {
		return fmt.Errorf("unknown %s command; use pagagateway %s help", role, role)
	}
	if action == "clients" && role != "server" {
		return errors.New("clients is only supported by server")
	}
	flags := flag.NewFlagSet(role, flag.ContinueOnError)
	flags.Usage = func() { _ = writeHelp(os.Stdout, role) }
	config := flags.String("config", "", "JSON configuration file (required for run/start; optional instance selector otherwise)")
	pidFile := flags.String("pidfile", "", "background state file (default: config path + .pid)")
	logFile := flags.String("log", "", fmt.Sprintf("background log file (default: %s.log beside config)", role))
	jsonOutput := flags.Bool("json", false, "output client list as JSON (server clients only)")
	if err := flags.Parse(remaining); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	foreground := action == "" || action == "run"
	if *config == "" && (foreground || action == "start") {
		return errors.New("-config is required")
	}
	if foreground && (*pidFile != "" || *logFile != "") {
		return errors.New("-pidfile and -log require a background command")
	}
	if action != "start" && *logFile != "" {
		return errors.New("-log requires start")
	}
	if *jsonOutput && action != "clients" {
		return errors.New("-json requires server clients")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if foreground {
		return runGateway(ctx, role, *config, nil)
	}
	if action == "clients" {
		return listBackgroundClients(ctx, *config, *pidFile, *jsonOutput)
	}
	if action != "start" {
		return manageBackground(ctx, action, role, *config, *pidFile)
	}
	configPath, err := filepath.Abs(*config)
	if err != nil {
		return err
	}
	statePath := *pidFile
	if statePath == "" {
		statePath = configPath + ".pid"
	}
	statePath, err = filepath.Abs(statePath)
	if err != nil {
		return err
	}
	if statePath == configPath || statePath+".lock" == configPath {
		return errors.New("-pidfile must not overwrite the configuration file")
	}
	logPath := *logFile
	if logPath == "" {
		logPath = filepath.Join(filepath.Dir(configPath), role+".log")
	}
	logPath, err = filepath.Abs(logPath)
	if err != nil {
		return err
	}
	if logPath == configPath || logPath == statePath || logPath == statePath+".lock" {
		return errors.New("-log must differ from the configuration and background state files")
	}
	return startBackground(ctx, role, configPath, statePath, logPath, "")
}

func runGateway(ctx context.Context, role, configPath string, ready func(*gateway.Server, bool) error) error {
	switch role {
	case "server":
		var configValue gateway.ServerConfig
		if err := gateway.LoadConfig(configPath, &configValue); err != nil {
			return err
		}
		s, err := gateway.NewServer(configValue)
		if err != nil {
			return err
		}
		listener, err := s.Listen()
		if err != nil {
			return err
		}
		defer listener.Close()
		if ready != nil {
			if err := ready(s, configValue.CertFile == ""); err != nil {
				return err
			}
		}
		log.Printf("Page server listening on %s", configValue.Listen)
		return s.Serve(ctx, listener)
	case "client":
		var configValue gateway.ClientConfig
		if err := gateway.LoadConfig(configPath, &configValue); err != nil {
			return err
		}
		c, err := gateway.NewClient(configValue)
		if err != nil {
			return err
		}
		if ready != nil {
			if err := ready(nil, strings.TrimSpace(configValue.Fingerprint) == ""); err != nil {
				return err
			}
		}
		return c.Run(ctx)
	default:
		return errors.New("unknown command")
	}
}

func certificate(args []string) error {
	f := flag.NewFlagSet("certificate", flag.ContinueOnError)
	f.Usage = func() { _ = writeHelp(os.Stdout, "certificate") }
	host := f.String("host", "localhost", "relay hostname or IP (certificate identity)")
	certFile := f.String("cert", "server.crt", "new certificate file")
	keyFile := f.String("key", "server.key", "new private key file")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: *host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(*host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{*host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// O_EXCL protects an existing deployment's certificate and key.
	kf, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}); err != nil {
		kf.Close()
		return err
	}
	if err = kf.Close(); err != nil {
		return err
	}
	cf, err := os.OpenFile(*certFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		_ = os.Remove(*keyFile)
		return err
	}
	if err = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		cf.Close()
		return err
	}
	if err = cf.Close(); err != nil {
		return err
	}
	digest := sha256.Sum256(der)
	fmt.Printf("Server certificate SHA256:%s\n", hex.EncodeToString(digest[:]))
	return nil
}
