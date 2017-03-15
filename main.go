package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rolandshoemaker/cat"

	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type server struct {
	work chan *submissionRequest

	certsCollection   *mgo.Collection
	chainsCollection  *mgo.Collection
	reportsCollection *mgo.Collection

	certParsers  []cat.CertParser
	chainParsers []cat.ChainParser
}

type submissionRequest struct {
	Certs            []*x509.Certificate
	ServerIP         net.IP
	ClientIP         net.IP
	Source           string
	Domain           string
	ASN              int
	ChainFingerprint []byte
}

func formToRequest(args url.Values) (*submissionRequest, error) {
	sr := &submissionRequest{}
	var certs []string
	err := json.Unmarshal([]byte(strings.Replace(args.Get("certlist"), " ", "+", -1)), &certs)
	if err != nil {
		return nil, err
	}
	for _, b := range certs {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// If there was some way of filtering out *obviously* misconstructed certs
			// information on what parsing failures we see here could be quite useful
			// to the Golang x509 team.
			return nil, err
		}
		sr.Certs = append(sr.Certs, cert)
	}
	sr.ServerIP = net.ParseIP(args.Get("server_ip"))
	sr.Source = args.Get("source")
	sr.Domain = args.Get("domain")
	if asn := args.Get("client_asn"); asn != "" {
		sr.ASN, err = strconv.Atoi(asn)
		if err != nil {
			return nil, err
		}
	}
	sr.ChainFingerprint, err = base64.StdEncoding.DecodeString(args.Get("chain_fp"))
	if err != nil {
		return nil, err
	}
	return sr, nil
}

func (srv *server) submissionHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("Failed to parse request form:", err)
		w.WriteHeader(400)
		return
	}
	sr, err := formToRequest(r.Form)
	if err != nil {
		fmt.Println("Failed to parse request:", err)
		w.WriteHeader(400)
		return
	}
	sr.ClientIP = net.ParseIP(r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
	go func() { srv.work <- sr }()
}

func (srv *server) doWork(workers int) {
	for i := 0; i < workers; i++ {
		go func() {
			for sr := range srv.work {
				srv.processSubmission(sr)
			}
		}()
	}
}

// not sure this is really possible but... who knows :/
func isChain(chain []*x509.Certificate) bool {
	return true
}

func (srv *server) processSubmission(sr *submissionRequest) {
	real := isChain(sr.Certs)
	if !real {
		return
	}

	chainID, err := srv.addChain(sr.Certs)
	if err != nil {
		// badd, what to do?
		fmt.Println("Failed to add chain:", err)
		return
	}

	err = srv.reportsCollection.Insert(bson.M{
		"submitted": time.Now(),
		"serverIP":  sr.ServerIP,
		"source":    sr.Source, // should check that this is something we expect
		"domain":    sr.Domain,
		"chainID":   chainID,
	})
	if err != nil {
		fmt.Println("Failed to add report:", err)
		return
	}
}

// this is pretty bad but... whatever :/
func chainID(chain []*x509.Certificate) string {
	hashes := []string{}
	for _, c := range chain {
		hashes = append(hashes, fmt.Sprintf("%x", sha256.Sum256(c.Raw)))
	}
	sort.Strings(hashes)
	h := sha256.New()
	for _, hStr := range hashes {
		h.Write([]byte(hStr))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (srv *server) addChain(chain []*x509.Certificate) (string, error) {
	id := chainID(chain)
	q := srv.chainsCollection.FindId(id)
	c, err := q.Count()
	if err != nil {
		// bad, return or try to insert anyway?
		return "", err
	}
	if c == 1 {
		// already exists, update count
		err = srv.chainsCollection.UpdateId(id, bson.M{
			"$inc": bson.M{
				"seen": 1,
			},
			"$set": bson.M{
				"lastSeen": time.Now(),
			},
		})
		if err != nil {
			// badddd
			return "", err
		}
		return id, nil
	}

	// process certs and insert
	certHashes := []string{}
	for _, c := range chain {
		hash, err := srv.addCertificate(c)
		if err != nil {
			// hrm... we have already added some stuff soooo... idk
			return "", err
		}
		certHashes = append(certHashes, hash)
	}

	// process the chain and insert
	chainData := cat.ProcessChain(chain, srv.chainParsers)

	now := time.Now()
	chainData["firstSeen"] = now
	chainData["lastSeen"] = now
	chainData["seen"] = 1
	chainData["contents"] = certHashes
	chainData["_id"] = id

	err = srv.chainsCollection.Insert(bson.M(chainData))
	if err != nil {
		return "", err
	}
	return id, nil
}

func (srv *server) addCertificate(cert *x509.Certificate) (string, error) {
	id := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	q := srv.certsCollection.FindId(id)
	c, err := q.Count()
	if err != nil {
		// bad, return or try to insert anyway?
		return "", err
	}
	if c == 1 {
		// already exists
		return id, nil
	}

	certData := cat.ProcessCertificate(cert, srv.certParsers)
	certData["_id"] = id

	err = srv.certsCollection.Insert(bson.M(certData))
	if err != nil {
		return "", err
	}
	return id, nil
}

func main() {
	mongoURL := flag.String("mongo", "", "")
	listenAddress := flag.String("listen", ":8080", "")
	certParserDir := flag.String("certParserDir", "", "")
	chainParserDir := flag.String("chainParserDir", "", "")
	workers := flag.Int("workers", 1, "")
	queueSize := flag.Int("queueSize", 1, "")
	flag.Parse()

	mongo, err := mgo.Dial(*mongoURL)
	if err != nil {
		panic(err)
	}
	db := mongo.DB("dsov2")
	if db == nil {
		panic("nil mongo db")
	}
	certsCollection := db.C("certs")
	if certsCollection == nil {
		panic("nil certs collection")
	}
	chainsCollection := db.C("chains")
	if chainsCollection == nil {
		panic("nil chains collection")
	}
	reportsCollection := db.C("reports")
	if reportsCollection == nil {
		panic("nil reports collection")
	}

	files, err := ioutil.ReadDir(*certParserDir)
	if err != nil {
		panic(err)
	}
	certParserPaths := []string{}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		if filepath.Ext(fi.Name()) != ".so" {
			continue
		}
		certParserPaths = append(certParserPaths, filepath.Join(*certParserDir, fi.Name()))
	}
	if len(certParserPaths) == 0 {
		panic("no cert parsers provided")
	}
	certParsers, err := cat.LoadCertParsers(certParserPaths)
	if err != nil {
		panic(err)
	}
	files, err = ioutil.ReadDir(*chainParserDir)
	if err != nil {
		panic(err)
	}
	chainParserPaths := []string{}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		if filepath.Ext(fi.Name()) != ".so" {
			continue
		}
		chainParserPaths = append(chainParserPaths, filepath.Join(*chainParserDir, fi.Name()))
	}
	if len(chainParserPaths) == 0 {
		panic("no chain parsers provided")
	}
	chainParsers, err := cat.LoadChainParsers(chainParserPaths)
	if err != nil {
		panic(err)
	}

	srv := &server{
		work:              make(chan *submissionRequest, *queueSize),
		certsCollection:   certsCollection,
		chainsCollection:  chainsCollection,
		reportsCollection: reportsCollection,
		certParsers:       certParsers,
		chainParsers:      chainParsers,
	}

	srv.doWork(*workers)

	http.HandleFunc("/", srv.submissionHandler)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		panic(err)
	}
}
