package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gpo-distributor/internal/model"
)

var version = "dev"

var validRepositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type clientConfig struct {
	server   string
	token    string
	insecure bool
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "upload":
		err = upload(os.Args[2:])
	case "profile-set":
		err = profileSet(os.Args[2:])
	case "policies":
		err = getList(os.Args[2:], "/api/v1/admin/policies")
	case "profiles":
		err = getList(os.Args[2:], "/api/v1/admin/profiles")
	case "clients":
		err = getList(os.Args[2:], "/api/v1/admin/clients")
	case "version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func common(fs *flag.FlagSet) (*string, *string, *bool) {
	server := fs.String("server", os.Getenv("GPO_SERVER_URL"), "server base URL")
	token := fs.String("token", os.Getenv("GPO_ADMIN_TOKEN"), "admin bearer token")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate validation (test only)")
	return server, token, insecure
}

func upload(args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	server, token, insecure := common(fs)
	policy := fs.String("policy", "", "policy name")
	file := fs.String("file", "", "GPO backup ZIP")
	note := fs.String("note", "", "version note")
	force := fs.Bool("force", false, "create a new version even when the semantic hash already exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := validateClient(*server, *token, *insecure)
	if err != nil {
		return err
	}
	if *policy == "" || *file == "" {
		return errors.New("-policy and -file are required")
	}
	if err := validateRepositoryName("-policy", *policy); err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		part, err := mw.CreateFormFile("bundle", filepath.Base(*file))
		if err == nil {
			_, err = io.Copy(part, f)
		}
		if err == nil && *note != "" {
			err = mw.WriteField("note", *note)
		}
		if err == nil && *force {
			err = mw.WriteField("force", "true")
		}
		closeErr := mw.Close()
		if err != nil {
			_ = pw.CloseWithError(err)
		} else if closeErr != nil {
			_ = pw.CloseWithError(closeErr)
		}
	}()

	endpoint := strings.TrimRight(cfg.server, "/") + "/api/v1/admin/policies/" + url.PathEscape(*policy) + "/versions"
	req, err := http.NewRequest(http.MethodPost, endpoint, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return doAndPrint(cfg, req)
}

func profileSet(args []string) error {
	fs := flag.NewFlagSet("profile-set", flag.ContinueOnError)
	server, token, insecure := common(fs)
	name := fs.String("name", "", "profile name")
	var policies multiFlag
	fs.Var(&policies, "policy", "ordered policy reference name@latest or name@version; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := validateClient(*server, *token, *insecure)
	if err != nil {
		return err
	}
	if *name == "" || len(policies) == 0 {
		return errors.New("-name and at least one -policy are required")
	}
	if err := validateRepositoryName("-name", *name); err != nil {
		return err
	}
	refs := make([]model.ProfilePolicy, 0, len(policies))
	for _, value := range policies {
		policy, ver, ok := strings.Cut(value, "@")
		if !ok || policy == "" || ver == "" {
			return fmt.Errorf("invalid policy reference %q; expected name@latest or name@version", value)
		}
		if err := validateRepositoryName("policy reference", policy); err != nil {
			return err
		}
		refs = append(refs, model.ProfilePolicy{Policy: policy, Version: ver})
	}
	body, _ := json.Marshal(map[string]any{"policies": refs})
	endpoint := strings.TrimRight(cfg.server, "/") + "/api/v1/admin/profiles/" + url.PathEscape(*name)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", "application/json")
	return doAndPrint(cfg, req)
}

func getList(args []string, path string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	server, token, insecure := common(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := validateClient(*server, *token, *insecure)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.server, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	return doAndPrint(cfg, req)
}

func validateRepositoryName(label, value string) error {
	if !validRepositoryName.MatchString(value) {
		return fmt.Errorf("invalid %s %q: must match %s (maximum 64 characters; no spaces)", label, value, validRepositoryName.String())
	}
	return nil
}

func validateClient(server, token string, insecure bool) (clientConfig, error) {
	if server == "" || token == "" {
		return clientConfig{}, errors.New("server and token are required")
	}
	u, err := url.Parse(server)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return clientConfig{}, errors.New("server must be an absolute URL")
	}
	if u.Scheme != "https" && !insecure {
		return clientConfig{}, errors.New("server must use https (or -insecure-skip-verify for tests)")
	}
	return clientConfig{server: server, token: token, insecure: insecure}, nil
}

func doAndPrint(cfg clientConfig, req *http.Request) error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.insecure} // #nosec G402: explicit test option.
	client := &http.Client{Transport: tr, Timeout: 15 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(body))
	}
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  gpoctl upload -server https://host:8443 -token TOKEN -policy NAME -file BACKUP.zip [-note TEXT] [-force]
  gpoctl profile-set -server URL -token TOKEN -name PROFILE -policy NAME@latest [-policy NAME@VERSION]
  gpoctl policies|profiles|clients -server URL -token TOKEN
  gpoctl version`)
}
