package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// Flags
var All bool
var Output bool
var Range int
var Timeout int
var Save string
var Channel int

func init() {
	addCmd.Flags().BoolVarP(&All, "all", "a", false, "Obtain a certificate regardless of validation")
	addCmd.Flags().BoolVarP(&Output, "output", "o", false, "Output JSON to Command Line")
	addCmd.Flags().IntVarP(&Range, "range", "r", 0, "Subnetmask (only IPv4) (8~30)")
	addCmd.Flags().IntVarP(&Timeout, "timeout", "t", 3000, "Timeout interval (milliseconds)")
	addCmd.Flags().StringVarP(&Save, "save", "s", "", "Save result to file (json)")
	addCmd.Flags().IntVarP(&Channel, "channel", "c", 10, "Number of 'go channel'")
	RootCmd.AddCommand(addCmd)
}

var addCmd = &cobra.Command{
	Use:   "get",
	Short: "get infomation of HTTPS certification.",
	Long:  "get infomation of HTTPS certification.",
	Run: func(cmd *cobra.Command, args []string) {
		main(args)
	},
}

func main(hosts []string) {
	if len(hosts) == 1 && len(strings.Split(hosts[0], ".")) == 4 && Range > 0 {
		host := hosts[0]
		ip := net.ParseIP(host)
		ipv4 := ip.To4()
		_, ipnet, err := net.ParseCIDR(host + "/" + strconv.Itoa(Range))
		if err != nil {
			log.Printf("%v", err)
		}
		min_adrs := [4]byte{}
		for i := 0; i < 4; i++ {
			a := ipv4[i]
			b := ipnet.Mask[i]
			min_adrs[i] = a & b
		}
		min_adrs[3] += 1
		max_adrs := [4]byte{}
		for i := 0; i < 4; i++ {
			a := ipv4[i]
			b := ^ipnet.Mask[i]
			max_adrs[i] = a | b
		}
		max_adrs[3] -= 1
		adrs_map := [4]int{}
		var host_num int
		host_num = 1
		for i := 0; i < len(ipnet.Mask); i++ {
			adrs_map[i] = 255 - int(ipnet.Mask[i])
			host_num *= 256 - int(ipnet.Mask[i])
		}
		host_num -= 2

		get_certs_subnet(Range, min_adrs, max_adrs)

	} else {
		get_certs(hosts)
	}
}

func output(JSON JSONResult) {
	if !Output {
		fmt.Println("Finished")
		if JSON.Result == nil {
			fmt.Print("Cannot get certificates")
		} else {
			for i, cert := range JSON.Result {
				if i == 0 {
					fmt.Print("Got certificates from : ")
				} else {
					fmt.Print(", ")
				}
				fmt.Print(cert.Host)
			}
		}
	}

	b, err := json.Marshal(JSON)
	if err != nil {
		fmt.Println(err)
	} else {
		if Output {
			fmt.Println(string(b))
		}
		if Save != "" {
			file, err := os.Create(Save)
			if err != nil {
				fmt.Println(err)
			}
			defer file.Close()
			file.Write(([]byte)(b))
		}
	}
}

func get_certs(hosts []string) {
	JSON := JSONResult{}
	JSON.Valid = All

	var wg sync.WaitGroup
	q := make(chan string, Channel)
	for i := 0; i < Channel; i++ {
		wg.Add(1)
		go worker_get_certs(&wg, q, &JSON)
	}

	for _, host := range hosts {
		q <- host
	}

	close(q)
	wg.Wait()

	output(JSON)
}

func get_certs_subnet(mask int, min_adrs, max_adrs [4]byte) {
	counter := 0
	JSON := JSONResult{}
	JSON.Valid = All

	var wg sync.WaitGroup
	q := make(chan string, Channel)
	for i := 0; i < Channel; i++ {
		wg.Add(1)
		go worker_get_certs(&wg, q, &JSON)
	}

	switch {
	case mask <= 30:
		adrs := net.IPv4(min_adrs[0], min_adrs[1], min_adrs[2], min_adrs[3]).To4()
		for i := 0; i < int(max_adrs[3]-min_adrs[3])+1; i++ {
			counter++
			q <- adrs.String()
			adrs[3] = byte(int(adrs[3]) + 1)
		}
		fallthrough
	case mask < 24:
		adrs := net.IPv4(min_adrs[0], min_adrs[1], min_adrs[2], 0).To4()
		for i := 0; i < int(max_adrs[2]-min_adrs[2]); i++ {
			adrs[2] = byte(int(adrs[2]) + 1)
			for j := 0; j < 256; j++ {
				adrs[3] = byte(j)
				counter++
				q <- adrs.String()
			}
		}
		fallthrough
	case mask < 16:
		adrs := net.IPv4(min_adrs[0], min_adrs[1], 0, 0).To4()
		for i := 0; i < int(max_adrs[1]-min_adrs[1]); i++ {
			adrs[1] = byte(int(adrs[1]) + 1)
			for j := 0; j < 256; j++ {
				adrs[2] = byte(j)
				for k := 0; k < 256; k++ {
					adrs[3] = byte(k)
					counter++
					q <- adrs.String()
				}
			}
		}
	}

	close(q)
	wg.Wait()

	output(JSON)
}

type JSONResult struct {
	Valid  bool       `json:"validation"`
	Result []CertJSON `json:"result"`
}

type CertJSON struct {
	Host  string              `json:"host"`
	Date  string              `json:"date"`
	Level int                 `json:"level"`
	Certs []*x509.Certificate `json:"certificates"`
}

func get_cert(host string) (bool, CertJSON) {
	log.Printf("Get certificates from %v", host)
	cJSON := CertJSON{}
	config := tls.Config{InsecureSkipVerify: All}
	dialer := net.Dialer{Timeout: time.Duration(Timeout) * time.Millisecond}
	conn, err := tls.DialWithDialer(&dialer, "tcp", host+":443", &config)
	if err != nil {
		log.Printf("error: " + err.Error())
		return false, cJSON
	} else {
		state := conn.ConnectionState()
		cJSON.Host = host
		cJSON.Date = time.Now().String()
		cJSON.Certs = state.PeerCertificates
		cJSON.Level = len(cJSON.Certs)
	}

	defer conn.Close()
	return true, cJSON
}

func worker_get_certs(wg *sync.WaitGroup, q chan string, rJSON *JSONResult) {
	defer wg.Done()
	for {
		host, ok := <-q
		if !ok {
			return
		}
		flag, Certs := get_cert(host)
		if flag {
			rJSON.Result = append(rJSON.Result, Certs)
		}
	}
}
