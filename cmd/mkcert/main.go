package main

import (
	"flag"
	"fmt"
	"log"
	"runtime/debug"

	"github.com/elagergren-spideroak/mkcert"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

func main() {
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if mkcert.Version != "" {
			fmt.Println(mkcert.Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(mkcert.CAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	if flag.NArg() == 0 && !*installFlag && !*uninstallFlag && *csrFlag != "" {
		flag.Usage()
		return
	}
	cfg := &mkcert.Config{
		InstallMode:   *installFlag,
		UninstallMode: *uninstallFlag,
		CSRPath:       *csrFlag,
		PKCS12:        *pkcs12Flag,
		ECDSA:         *ecdsaFlag,
		Client:        *clientFlag,
		CertFile:      *certFileFlag,
		KeyFile:       *keyFileFlag,
		P12File:       *p12FileFlag,
	}
	if err := cfg.Run(flag.Args()); err != nil {
		log.Fatal(err)
	}
}
