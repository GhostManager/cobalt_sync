package internal

// @its_a_feature_ 8/30/2023
import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func checkin(url string) {
	if url != "" {
		for {
			req, err := http.NewRequest("GET", url, nil)
			resp, err := client.Do(req)
			if err != nil {
				log.Println("[-] Error checking in:", err)
			} else if resp.StatusCode != 200 {
				log.Println("[-] Error checking in response code:", resp.StatusCode)
			} else {
				log.Println("[+] Successfully checked in with cobalt_web and ghostwriter")
				return
			}
			time.Sleep(2 * time.Second)
		}

	}
}

func emitNewData[V *beacon | *event](b V, url string, hash string) {
	if url != "" {
		log.Println("[*] trying to emitNewData")
		jsonBytes, err := json.Marshal(b)
		if err != nil {
			log.Println("[-] Failed to marshal Beacon data into JSON: ", err)
			return
		}
		for i := 0; i < 10; i++ {
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
			resp, err := limitingHTTPClient.Do(req)
			if err != nil {
				log.Println("[-] error client.Do: ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			if resp.StatusCode != 201 {
				log.Println("[-] error resp.StatusCode: ", resp.StatusCode)
				time.Sleep(10 * time.Second)
			} else {
				hashChannel <- hash
				return
			}
		}
	} else {
		hashChannel <- hash
	}
}

func SetURL(url string) {
	targetURL = url
	if url != "" {
		checkin(targetURL + "/checkin")
	}
}
