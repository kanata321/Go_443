package cmd

import (
    "github.com/spf13/cobra"
    "crypto/tls"
	"log"
    "net"
    "strings"
    "strconv"
    "time"
)

var All bool
var Range int

func init() {
    addCmd.Flags().BoolVarP(&All, "all", "a", false, "List all instances")
    addCmd.Flags().IntVarP(&Range, "range", "r", 0, "IP range")
    RootCmd.AddCommand(addCmd)
}

var addCmd = &cobra.Command{
    Use:   "get",
    Short: "get infomation of HTTPS certification.",
    Long:  "get infomation of HTTPS certification.",
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) == 1 {
            get(args[0])
        }
    },
}

func get (host string){

    if len(strings.Split(host, ".")) == 4 {
        log.Printf("ipv%v", 4)
        ip := net.ParseIP(host)
        ipv4 := ip.To4()
        if Range > 0 {
            _, ipnet, err := net.ParseCIDR(host+"/"+strconv.Itoa(Range))
            if err != nil {
                log.Printf("%v", err)
            }
            min_adrs := [4] byte{}
            for i := 0; i < 4; i++{
                a := ipv4[i]
                b := ipnet.Mask[i]
                min_adrs[i] = a & b;
            }
            min_adrs[3] += 1
            max_adrs := [4] byte{}
            for i := 0; i < 4; i++{
                a := ipv4[i]
                b := ^ipnet.Mask[i]
                max_adrs[i] = a | b
            }
            max_adrs[3] -= 1
            log.Printf("min_adrs:%v", min_adrs)
            log.Printf("max_adrs:%v", max_adrs)
            // for _, v := range ipnet {
            //     get_cert_info(string(v))
            // }
            adrs_map := [4] int{}
            var host_num int
            host_num = 1 
            for i := 0; i < len(ipnet.Mask); i++{
                adrs_map[i] = 255 - int(ipnet.Mask[i])
                host_num *= 256 - int(ipnet.Mask[i])
            }
            host_num -= 2 
            
            log.Printf("host_num:%v", host_num)
            
            start_adrs1 := net.IPv4(min_adrs[0],min_adrs[1],min_adrs[2],min_adrs[3]).To4()
            for i := 0; i < int(max_adrs[3]); i++{
                get_cert_info(start_adrs1.String());
                start_adrs1[3] = byte(int(start_adrs1[3])+1)
                log.Printf("adrs:%v", start_adrs1)
            }
            // start_adrs2 := net.IPv4(min_adrs[0],min_adrs[1],min_adrs[2], 0x01).To4()
            // for i := 1; i < int(max_adrs[2])+1; i++{
            //     for j := 0; j < int(max_adrs[3])+1; j++{
            //         get_cert_info(start_adrs2.String());
            //         start_adrs2[3] = byte(int(start_adrs2[3])+1)
            //         log.Printf("adrs:%v", start_adrs2)
            //     }
            //     start_adrs2[2] = byte(int(start_adrs2[2])+1)
            // }
            // start_adrs3 := net.IPv4(min_adrs[0],min_adrs[1],min_adrs[2], 0x01).To4()
            // for i := 1; i < int(max_adrs[1])+1; i++{
            //     for j := 1; j < int(max_adrs[2])+1; j++{
            //         for k := 0; k < int(max_adrs[1])+1; k++{
            //             get_cert_info(start_adrs3.String());
            //             start_adrs3[3] = byte(int(start_adrs3[3])+1)
            //             log.Printf("adrs:%v", start_adrs3)
            //         }
            //         start_adrs3[2] = byte(int(start_adrs3[2])+1)
            //     }
            //     start_adrs3[1] = byte(int(start_adrs3[1])+1)
            // }
            // start_adrs4 := net.IPv4(min_adrs[0],min_adrs[1],min_adrs[2], 0x00).To4()
            // for i := 1; i < int(max_adrs[0])+1; i++{
            //     start_adrs4[0] = byte(int(start_adrs4[0])+1)
            //     for j := 1; j < int(max_adrs[1])+1; j++{
            //         start_adrs4[1] = byte(int(start_adrs4[1])+1)
            //         for k := 1; k < int(max_adrs[2])+1; k++{
            //             start_adrs4[2] = byte(int(start_adrs4[2])+1)
            //             for l := 0; l < int(max_adrs[3])+1; l++{
            //                 get_cert_info(start_adrs4.String());
            //                 start_adrs4[3] = byte(int(start_adrs4[3])+1)
            //                 log.Printf("adrs:%v", start_adrs4)
            //             }
            //         }
            //     }
            // }
            
        }
    }else {
        get_cert_info(host);
    }

}

func get_cert_info(host string){
    
    config := tls.Config{}
    dialer := net.Dialer{Timeout: 50 * time.Millisecond}
    conn, err := tls.DialWithDialer(&dialer,"tcp", host+":443", &config)
	if err != nil {
		log.Printf("host: " + host + ", error: " + err.Error())
        return
	} else {
	    state := conn.ConnectionState()
	    certs := state.PeerCertificates
        for num, certArray := range certs {
		    log.Printf("num:%v", num)
		    log.Printf("%v", certArray)
	    }
    }

	defer conn.Close()
	
}
