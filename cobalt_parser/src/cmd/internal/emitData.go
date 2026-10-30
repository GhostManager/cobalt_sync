package internal

// @its_a_feature_ 8/30/2023
import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func checkin(url string) {
	if url != "" {
		for {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Println("[-] Invalid check-in URL:", err)
				return
			}
			resp, err := client.Do(req)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
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

func emitNewData[V *beacon | *event | *eventWithContext](b V, url string, hash string) {
	// Retry delivery errors with a delay; release the hash for malformed events or URLs.
	if url != "" {
		log.Println("[*] trying to emitNewData")
		jsonBytes, err := json.Marshal(b)
		if err != nil {
			log.Println("[-] Failed to marshal Beacon data into JSON: ", err, hash)
			hashChannel <- hash
			return
		}
		for {
			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
			if err != nil {
				log.Println("[-] Invalid delivery URL:", err)
				hashChannel <- hash
				return
			}
			resp, err := limitingHTTPClient.Do(req)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			if err != nil {
				log.Println("[-] error client.Do: ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			if resp.StatusCode != 201 {
				log.Println("[-] error resp.StatusCode: ", resp.StatusCode)
				time.Sleep(10 * time.Second)
			} else {
				// successfully sent it out, move on
				log.Println("[+] successfully sent data to cobalt_web: ", hash)
				return
			}
		}
	}
}

func SetURL(url string) {
	targetURL = url
	if url != "" {
		checkin(targetURL + "/checkin")
	}
}
