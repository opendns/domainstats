/*
This program takes a list of domains and queries each against the OpenDNS
Investigate API, optionally outputting a CSV file.

Because querying every endpoint can be very time consuming, this program uses
a TOML file to configure which information should be queried.

For full documentation of usage, see the GitHub page:
https://github.com/dead10ck/domainstats
*/
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"

	domainstats "github.com/dead10ck/domainstats/internal"
	"github.com/dead10ck/goinvestigate"
)

type opt struct {
	verbose    bool
	setup      string
	outFile    string
	configPath string
}

var (
	opts       opt
	numDomains int
)

const (
	DEFAULT_MAX_GOROUTINES = 5
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {

	flag.BoolVar(&opts.verbose, "v", false, "Print out verbose log messages.")
	flag.StringVar(&opts.setup, "setup", "",
		"Generate a default config file in ~/.domainstats/default.toml with"+
			" the given API key.")
	flag.StringVar(&opts.outFile, "out", "", "Output matching IPs to the given file")
	flag.StringVar(&opts.configPath, "c", domainstats.DefaultConfigPath, "The config file to use")
	flag.Parse()

	if opts.setup != "" {
		err := domainstats.GenerateDefaultConfig(opts.setup)
		if err != nil {
			log.Fatalf("error creating default config file: %v", err)
		}

		fmt.Printf(fmt.Sprintf("Config file generated in %s\n", domainstats.DefaultConfigPath))
		os.Exit(0)
	}

	// if the default config file does not exist and the user did not specify
	// a different config file, then the program cannot proceed
	if _, err := os.Stat(domainstats.DefaultConfigPath); os.IsNotExist(err) && opts.configPath == domainstats.DefaultConfigPath {
		log.Fatal("Default config file missing, and no other config file specified." +
			" Please run domainstats with the -setup option to set up a default " +
			"config file.")
	}

	config, err := domainstats.NewConfig(opts.configPath)
	if err != nil {
		log.Fatal(err)
	}
	var outWriter *csv.Writer
	inv := goinvestigate.New(config.APIKey)
	domainListFileName := flag.Arg(flag.NArg() - 1)
	if domainListFileName == "" {
		fmt.Println("Need a file name")
		os.Exit(-1)
	}
	inChan := readDomainsFrom(domainListFileName)

	if opts.verbose {
		inv.SetVerbose(true)
	}

	if opts.outFile != "" {
		outFile, err := os.Create(opts.outFile)
		if err != nil {
			log.Fatal(err)
		}
		outWriter = csv.NewWriter(outFile)
		outWriter.Comma = rune('\t')
		outWriter.Write(config.DeriveHeader())
		defer func() {
			outWriter.Flush()
			outFile.Close()
		}()
	}

	outChan := getInfo(config, inv, inChan)
	mainWg := new(sync.WaitGroup)

	mainWg.Add(1)
	go writeOut(outWriter, outChan, mainWg)

	mainWg.Wait()
}

func writeOut(outWriter *csv.Writer, outChan <-chan []string, wg *sync.WaitGroup) {
	numProcessed := 0
	msgChan := make(chan string, 10)
	go printStdOut(msgChan)

	for respRow := range outChan {
		numProcessed++
		msgChan <- fmt.Sprintf("\r%d/%d: %s", numProcessed, numDomains, respRow[0])
		if outWriter != nil {
			outWriter.Write(respRow)
		}
	}

	close(msgChan)
	wg.Done()
}

func printStdOut(msgChan <-chan string) {
	for msg := range msgChan {
		fmt.Printf("\r%120s", " ")
		fmt.Print(msg)
	}
	fmt.Println()
}

// The goroutine which does the HTTP queries
func query(qChan <-chan *domainstats.DomainQueryMessage) {
	for m := range qChan {
		m.RespChan <- m.Q.Query()
	}
}

func process(inv *goinvestigate.Investigate, config *domainstats.Config,
	domainChan <-chan string,
	qChan chan<- *domainstats.DomainQueryMessage,
	outChan chan<- []string,
	wg *sync.WaitGroup) {

domainLoop:
	for domain := range domainChan {

		// generate the list of queries to make for each domain
		queries := config.DeriveMessages(inv, domain)

		// send each query on the query channel for the query goroutines
		// to receive
		for _, q := range queries {
			qChan <- q
		}

		row := []string{domain}
		// receive once for each query that was sent
		for _, q := range queries {
			qmResp := <-q.RespChan
			if qmResp.Err != nil {
				log.Printf("error during query for %v: %v\nskipping this domain",
					domain, qmResp.Err)
				continue domainLoop
			}
			subRow, err := config.ExtractCSVSubRow(qmResp.Resp)
			if err != nil {
				inv.Logf("error extracting CSV sub row: %v", err)
				continue
			}
			row = append(row, subRow...)
		}

		outChan <- row
	}
	wg.Done()
}

func getInfo(config *domainstats.Config, inv *goinvestigate.Investigate, domainChan <-chan string) <-chan []string {
	outChan := make(chan []string, 100)
	qChan := make(chan *domainstats.DomainQueryMessage)
	wg := new(sync.WaitGroup)

	// launch the query goroutines
	for i := 0; i < DEFAULT_MAX_GOROUTINES; i++ {
		go query(qChan)
	}

	// launch the processor goroutines
	for i := 0; i < DEFAULT_MAX_GOROUTINES; i++ {
		wg.Add(1)
		go process(inv, config, domainChan, qChan, outChan, wg)
	}

	// launch a goroutine which closes the output channel when the processor
	// goroutines are finished
	go func() {
		wg.Wait()
		close(qChan)
		close(outChan)
	}()

	return outChan
}

func readDomainsFrom(fName string) <-chan string {
	file, err := os.Open(fName)

	if err != nil {
		log.Fatalf("\nError opening domain list %s: %v\n", fName, err)
	}

	domainChan := make(chan string, 100)

	scanner := bufio.NewScanner(file)

	go func() {
		for scanner.Scan() {
			domainChan <- scanner.Text()
			numDomains++
		}
		close(domainChan)
		file.Close()
	}()

	return domainChan
}
