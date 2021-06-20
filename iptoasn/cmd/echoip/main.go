package main

import (
	"flag"
	"log"

	"os"

	"github.com/mpolden/echoip/http"
	"github.com/mpolden/echoip/iputil"
	"github.com/mpolden/echoip/iputil/geo"
)

type multiValueFlag []string

func (f *multiValueFlag) String() string {
	vs := ""
	for i, v := range *f {
		vs += v
		if i < len(*f)-1 {
			vs += ", "
		}
	}
	return vs
}

func (f *multiValueFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	countryFile := flag.String("f", "/data/GeoLite2-Country.mmdb", "Path to GeoIP country database")
	cityFile := flag.String("c", "/data/GeoLite2-City.mmdb", "Path to GeoIP city database")
	asnFile := flag.String("a", "/data/GeoLite2-ASN.mmdb", "Path to GeoIP ASN database")
	listen := flag.String("l", ":8080", "Listening address")
	reverseLookup := flag.Bool("r", false, "Perform reverse hostname lookups")
	portLookup := flag.Bool("p", false, "Enable port lookup")
	template := flag.String("t", "index.html", "Path to template")
	cacheSize := flag.Int("C", 0, "Size of response cache. Set to 0 to disable")
	profile := flag.Bool("P", false, "Enables profiling handlers")
	var headers multiValueFlag
	flag.Var(&headers, "H", "Header to trust for remote IP, if present (e.g. X-Real-IP)")
	flag.Parse()

	log := log.New(os.Stderr, "echoip: ", 0)
	r, err := geo.Open(*countryFile, *cityFile, *asnFile)
	if err != nil {
		log.Fatal(err)
	}
	cache := http.NewCache(*cacheSize)
	server := http.New(r, cache, *profile)
	server.IPHeaders = headers
	if _, err := os.Stat(*template); err == nil {
		server.Template = *template
	} else {
		log.Printf("Not configuring default handler: Template not found: %s", *template)
	}
	if *reverseLookup {
		log.Println("Enabling reverse lookup")
		server.LookupAddr = iputil.LookupAddr
	}
	if *portLookup {
		log.Println("Enabling port lookup")
		server.LookupPort = iputil.LookupPort
	}
	if len(headers) > 0 {
		log.Printf("Trusting remote IP from header(s): %s", headers.String())
	}
	if *cacheSize > 0 {
		log.Printf("Cache capacity set to %d", *cacheSize)
	}
	if *profile {
		log.Printf("Enabling profiling handlers")
	}
	log.Printf("Listening on http://%s", *listen)
	if err := server.ListenAndServe(*listen); err != nil {
		log.Fatal(err)
	}
}
