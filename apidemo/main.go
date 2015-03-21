package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/dgryski/go-duoweb"

	"launchpad.net/goyaml"
)

func main() {

	userid := flag.String("u", "", "user id to authenticate")
	cfgFile := flag.String("c", "keys.yml", "config file")

	flag.Parse()

	if *userid == "" {
		flag.Usage()
		return
	}

	cfgData, err := ioutil.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("unable to load config file %s: %s\n", *cfgFile, err)
	}

	var cfg struct {
		Ikey string
		Skey string
		Akey string
		Host string
	}

	goyaml.Unmarshal(cfgData, &cfg)

	c := duoweb.Client{
		IKey: cfg.Ikey,
		SKey: cfg.Skey,
		Host: cfg.Host,
	}

	r, _ := c.Ping()
	fmt.Printf("r = %+v\n", r)

	r, _ = c.Check()
	fmt.Printf("r = %+v\n", r)

	m, err := c.AuthPush(*userid, true)

	log.Printf("m	 = %+v\n", m)

	txid := m.Txid

	for i := 0; m.Result != "allow" && m.Result != "deny" && i < 30; i++ {
		m, err = c.PollAuthStatus(txid)
		log.Printf("i %d, m = %+v, err = %v\n", i, m, err)
		time.Sleep(1 * time.Second)
	}
}
