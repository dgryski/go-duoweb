package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/dgryski/go-duoweb"
	"launchpad.net/goyaml"
)

func main() {
	port := flag.Int("p", 8080, "port to listen on")
	cfgFile := flag.String("c", "keys.yml", "config file")

	cfgData, err := ioutil.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("unable to load config file %s: %s\n", *cfgFile, err)
	}

	var cfg struct {
		Ikey string
		Skey string
		Akey string
		Host string
	}

	goyaml.Unmarshal(cfgData, &cfg)

	// set up handler to serve our static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "GET" {

			user := r.FormValue("user")

			if user == "" {
				http.Error(w, "user query parameter required", 200)
				return
			}

			var sigRequest string
			var err error

			if enroll := r.FormValue("enroll"); enroll == "1" {
				sigRequest, err = duoweb.SignEnrollRequest(cfg.Ikey, cfg.Skey, cfg.Akey, user)
			} else {
				sigRequest, err = duoweb.SignRequest(cfg.Ikey, cfg.Skey, cfg.Akey, user)
			}

			if err != nil {
				http.Error(w, "error processing request", http.StatusInternalServerError)
			}

			var tmplParams = struct {
				Host       string
				SigRequest string
			}{
				Host:       cfg.Host,
				SigRequest: sigRequest,
			}

			getTMPL.Execute(w, tmplParams)

			return
		}

		if r.Method != "POST" {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		sigResponse := strings.TrimSpace(r.FormValue("sig_response"))

		username := duoweb.VerifyResponse(cfg.Ikey, cfg.Skey, cfg.Akey, sigResponse)
		action := "authenticated"

		if username == "" {
			// try as enrollment request
			username = duoweb.VerifyEnrollResponse(cfg.Ikey, cfg.Skey, cfg.Akey, sigResponse)

			// nope ..
			if username == "" {
				failTMPL.Execute(w, nil)
				return
			}

			action = "enrolled"
		}

		// success!
		var tmplParams = struct {
			User   string
			Action string
		}{
			User:   username,
			Action: action,
		}

		welcomeTMPL.Execute(w, tmplParams)
	})

	portStr := fmt.Sprintf(":%d", *port)
	log.Println("Listening on", portStr)
	log.Fatal("ListenAndServe:", http.ListenAndServe(portStr, nil))
}

var getTMPL = template.Must(template.New("gettmpl").Parse(
	`<html><head></head>
<body>
    <script src='/static/Duo-Web-v1.bundled.min.js'></script>
    <script>
        Duo.init({'host':'{{ .Host }}', 'sig_request':'{{ .SigRequest }} '});
    </script>
    <iframe height='500' width='620' frameborder='0' id='duo_iframe' />
</body>`))

var welcomeTMPL = template.Must(template.New("welcome").Parse(
	`<html><head></head>
<body>
{{ .User }} successfully {{ .Action }} with Duo.
</body>`))

var failTMPL = template.Must(template.New("fail").Parse(
	`<html><head></head>
<body>
Authentication failure
</body>`))
