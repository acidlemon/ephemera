package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/acidlemon/ephemera/auth"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fujiwara/ridge"
	"github.com/gorilla/sessions"
)

type HostRecord struct {
	Subdomain string    `json:"subdomain"`
	Target    string    `json:"target"`
	ExpireAt  time.Time `json:"expire_at"`
	NeedAuth  bool      `json:"need_auth"`
}

type AuthorityRecords map[string][]string

const region = "ap-northeast-1"

var (
	store          *sessions.CookieStore
	bucketName     string
	hostsKey       string
	authoritiesKey string
	hostSuffix     string
	authSubdomain  string
	clientID       string
	clientSecret   string
)

func MustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s is not set", key)
	}
	return value
}

func initialize() {
	hostsKey = "hosts.json"
	authoritiesKey = "authorities.json"

	bucketName = MustEnv("EPHEMERA_S3_BUCKET_NAME")
	hostSuffix = MustEnv("EPHEMERA_HOST_SUFFIX")
	authSubdomain = MustEnv("EPHEMERA_AUTH_SUBDOMAIN")
	clientID = MustEnv("EPHEMERA_CLIENT_ID")
	clientSecret = MustEnv("EPHEMERA_CLIENT_SECRET")

	storekey := MustEnv("EPHEMERA_SESSION_KEY")
	store = auth.NewCookieStore(storekey)
}

func fetchConfigRecords() ([]*HostRecord, AuthorityRecords, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	s3client := s3.NewFromConfig(cfg)
	hosts := []*HostRecord{}
	authorities := AuthorityRecords{}
	{
		result, err := s3client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(hostsKey),
		})
		if err != nil {
			log.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, hostsKey, err)
			return nil, nil, err
		}
		defer result.Body.Close()

		err = json.NewDecoder(result.Body).Decode(&hosts)
		if err != nil {
			log.Printf("Couldn't decode json. Here's why: %v\n", err)
			return nil, nil, err
		}
	}

	{
		result, err := s3client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(authoritiesKey),
		})
		if err != nil {
			log.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, authoritiesKey, err)
			return nil, nil, err
		}
		defer result.Body.Close()

		err = json.NewDecoder(result.Body).Decode(&authorities)
		if err != nil {
			log.Printf("Couldn't decode json. Here's why: %v\n", err)
			return nil, nil, err
		}
	}

	return hosts, authorities, nil
}

func GeneralHandler(w http.ResponseWriter, req *http.Request) {
	hosts, authorities, err := fetchConfigRecords()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"failed to fetch config:` + err.Error() + `"}`))
		return
	}
	now := time.Now()

	// check auth subdomain
	subdomain := strings.Split(req.Header.Get("X-Forwarded-Host"), ".")[0]
	if subdomain == authSubdomain {
		authServer, err := auth.NewServer(&auth.ServerOptions{
			CookieStore:   store,
			ClientID:      clientID,
			ClientSecret:  clientSecret,
			HostSuffix:    hostSuffix,
			AuthSubdomain: authSubdomain,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message":"failed to create auth server:` + err.Error() + `"}`))
			return
		}
		log.Println("authServer.ServeHTTP")
		authServer.ServeHTTP(w, req)
		return
	}

	for _, host := range hosts {
		if host.Subdomain == subdomain && host.ExpireAt.After(now) {
			// need auth?
			if host.NeedAuth {
				loginSession := auth.ExtractSession(req, store)
				if loginSession.Email == "" {
					// not logged in
					session, err := store.New(req, "ephemera_gate")
					if err != nil {
						log.Println("failed to create gate session:", err.Error())
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					session.Options.Domain = hostSuffix
					session.Options.SameSite = http.SameSiteNoneMode
					session.Values["subdomain"] = subdomain
					session.Values["path"] = req.URL.Path
					session.Save(req, w)
					http.Redirect(w, req, fmt.Sprintf("https://%s.%s/auth/sign_in", authSubdomain, hostSuffix), http.StatusFound)
					return
				} else {
					if subdomains, ok := authorities[loginSession.Email]; ok {
						if !slices.Contains(subdomains, subdomain) && !slices.Contains(subdomains, "*") {
							// unauthorized
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
					} else {
						// unauthorized
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
			}

			destUrl, _ := url.Parse("http://" + host.Target)
			rp := httputil.NewSingleHostReverseProxy(destUrl)
			rp.ServeHTTP(w, req)

			// buff := &bytes.Buffer{}
			// rp.ServeHTTP(&responseDumper{w, io.MultiWriter(w, buff)}, req)
			// log.Println("Response: ", buff.String())
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
	<title>404 Not Found</title>
</head>
<body>
	<h1>Not Found</h1>
	<p>The requested URL was not found on this server.</p>
</body>
</html>
`))
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)

	initialize()

	mux := http.NewServeMux()
	mux.HandleFunc("/", GeneralHandler)
	ridge.Run(":5003", "/", mux)
}
