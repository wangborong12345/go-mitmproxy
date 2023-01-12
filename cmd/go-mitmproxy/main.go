package main

import (
	"flag"
	"fmt"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	rawLog "log"
	"os"

	"github.com/lqqyt2423/go-mitmproxy/addon"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/web"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	debug    int
	version  bool
	certPath string

	addr         string
	webAddr      string
	ssl_insecure bool

	dump      string // dump filename
	dumpLevel int    // dump level

	mapperDir string
	automatic bool
}

func loadConfig() *Config {
	config := new(Config)

	flag.IntVar(&config.debug, "debug", 0, "debug mode: 1 - print debug log, 2 - show debug from")
	flag.BoolVar(&config.version, "version", false, "show version")
	flag.StringVar(&config.addr, "addr", ":9080", "proxy listen addr")
	flag.StringVar(&config.webAddr, "web_addr", ":9081", "web interface listen addr")
	flag.BoolVar(&config.ssl_insecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&config.dump, "dump", "", "dump filename")
	flag.IntVar(&config.dumpLevel, "dump_level", 0, "dump level: 0 - header, 1 - header + body")
	flag.StringVar(&config.mapperDir, "mapper_dir", "", "mapper files dirpath")
	flag.StringVar(&config.certPath, "cert_path", "", "path of generate cert files")
	flag.BoolVar(&config.automatic, "automatic", false, "automatically config")
	flag.Parse()

	return config
}

func main() {
	config := loadConfig()

	if config.debug > 0 {
		rawLog.SetFlags(rawLog.LstdFlags | rawLog.Lshortfile)
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if config.debug == 2 {
		log.SetReportCaller(true)
	}
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	opts := &proxy.Options{
		Debug:             config.debug,
		Addr:              config.addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.ssl_insecure,
		CaRootPath:        config.certPath,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if config.version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	log.Infof("go-mitmproxy version %v\n", p.Version)

	p.AddAddon(&proxy.LogAddon{})
	p.AddAddon(web.NewWebAddon(config.webAddr))

	if config.dump != "" {
		dumper := addon.NewDumperWithFilename(config.dump, config.dumpLevel)
		p.AddAddon(dumper)
	}

	if config.mapperDir != "" {
		mapper := addon.NewMapper(config.mapperDir)
		p.AddAddon(mapper)
	}

	if config.automatic {
		certificate := p.GetCertificate()
		err := cert.AddInstallList(certificate)
		if err != nil {
			log.Errorf("automatic install certificate error:%s", err)
		}
	}

	log.Fatal(p.Start())
}
