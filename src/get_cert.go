package main

import (
	"crypto/tls"
	"log"
)

func main() {

	config := tls.Config{}

	host := "dk-home-dir.asuscomm.com"

	conn, err := tls.Dial("tcp", host+":443", &config)
	if err != nil {
		log.Fatal("host: " + host + ", error: " + err.Error())
	}

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	defer conn.Close()

	for num, cert := range certs {
		log.Printf("num:%v", num)
		log.Printf("%v", cert)
	}
}
