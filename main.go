package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed templates/*.html
var rawTemplates embed.FS

var templates *template.Template

func init() {
	// Parse the embedded templates once during initialization
	var err error
	templates, err = template.ParseFS(rawTemplates, "templates/*")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	selfURL := os.Getenv("SELF_URL")
	privkey, pubkey := os.Getenv("AGE_PRIVATE_KEY"), os.Getenv("AGE_PUBLIC_KEY")
	if err := os.WriteFile("key.txt", []byte(privkey), 0600); err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ciphertext := r.URL.Query().Get("c")
		if ciphertext == "" {
			w.Header().Add("Content-Type", "text/html")
			templates.ExecuteTemplate(w, "index.html", nil)
			return
		}

		// The caller provided ciphertext, decrypt it
		userID := r.Header.Get("X-Forwarded-Email")
		userGroups := r.Header.Get("X-Forwarded-Groups")
		if !strings.Contains(userGroups, "leadership") {
			http.Error(w, "you must be a member of the leadership group to decrypt values", 403)
			return
		}

		js := &bytes.Buffer{}

		cmd := exec.CommandContext(r.Context(), "age", "--decrypt", "-i", "key.txt")
		cmd.Stderr = os.Stderr
		cmd.Stdout = js
		cmd.Stdin = base64.NewDecoder(base64.RawURLEncoding, bytes.NewBufferString(r.URL.Query().Get("c")))
		if err := cmd.Run(); err != nil {
			log.Printf("age --decrypt failed (stderr was passed through) err=%s", err)
			http.Error(w, "decryption error or invalid input", 400)
			return
		}

		p := &payload{}
		if err := json.Unmarshal(js.Bytes(), p); err != nil {
			http.Error(w, "invalid input", 400)
			return
		}

		log.Printf("decrypted value %q for user %q originally encrypted by %q", p.Description, userID, p.EncryptedByUser)
		w.Header().Add("Content-Type", "text/html")
		templates.ExecuteTemplate(w, "decrypted.html", p)
	})

	http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-Forwarded-Email")

		p := &payload{
			EncryptedByUser: userID,
			EncryptedAt:     time.Now().UTC().Unix(),
			Description:     r.FormValue("desc"),
			Value:           r.FormValue("value"),
		}
		js, err := json.Marshal(p)
		if err != nil {
			panic(err) // unlikely
		}

		ciphertext := &bytes.Buffer{}

		cmd := exec.CommandContext(r.Context(), "age", "--encrypt", "-r", pubkey)
		cmd.Stderr = os.Stderr
		cmd.Stdout = ciphertext
		cmd.Stdin = bytes.NewBuffer(js)
		if err := cmd.Run(); err != nil {
			log.Printf("age --encrypt failed (stderr was passed through) err=%s", err)
			http.Error(w, "encryption error", 500)
			return
		}

		w.Header().Add("Content-Type", "text/html")
		templates.ExecuteTemplate(w, "encrypted.html", map[string]any{
			"url": selfURL + "?c=" + base64.RawURLEncoding.EncodeToString(ciphertext.Bytes()),
		})
	})

	panic(http.ListenAndServe(":8080", nil))
}

type payload struct {
	EncryptedByUser string `json:"eb"`
	EncryptedAt     int64  `json:"ea"` // seconds since unix epoch utc
	Description     string `json:"d"`
	Value           string `json:"v"`
}
