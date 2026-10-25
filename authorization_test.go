// Copyright 2026 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

package golink

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/xsrftoken"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func testLocalClient(t *testing.T, handler http.Handler) *local.Client {
	t.Helper()
	api := httptest.NewServer(handler)
	t.Cleanup(api.Close)
	return &local.Client{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", api.Listener.Addr().String())
	}}
}

func TestAllowUnknownUsersProtectsAuthenticatedWrites(t *testing.T) {
	profile := &tailcfg.UserProfile{ID: 101, LoginName: "alice@example.com"}
	lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/whois":
			if r.URL.Query().Get("addr") == "192.0.2.1:1234" {
				http.Error(w, "unknown peer", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(apitype.WhoIsResponse{
				Node: &tailcfg.Node{User: profile.ID}, UserProfile: profile,
			})
		case "/localapi/v0/status":
			json.NewEncoder(w).Encode(ipnstate.Status{
				CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"},
				User:           map[tailcfg.UserID]tailcfg.UserProfile{profile.ID: *profile},
			})
		case "/localapi/v0/prefs":
			json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
		default:
			http.NotFound(w, r)
		}
	}))
	for _, mode := range []string{"ordinary", "service"} {
		for _, operation := range []string{"create", "update"} {
			for _, auth := range []string{"none", "token", "home-token", "header", "anonymous"} {
				t.Run(mode+"/"+operation+"/"+auth, func(t *testing.T) {
					db, err := NewSQLiteDB(":memory:")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { db.db.Close() })
					s, err := New(Options{DB: db, LocalClient: lc, AllowUnknownUsers: true})
					if err != nil {
						t.Fatal(err)
					}
					if mode == "service" {
						s.serviceName = "svc:golink"
					}
					post := func(long, auth string) *httptest.ResponseRecorder {
						data := url.Values{"short": {"protected"}, "long": {long}}
						if auth == "token" || auth == "home-token" {
							scope := newShortName
							if operation == "update" && auth == "token" {
								scope = "protected"
							}
							data.Set("xsrf", xsrftoken.Generate(s.xsrfKey, profile.LoginName, scope))
						}
						r := httptest.NewRequest("POST", "http://go/", strings.NewReader(data.Encode()))
						r.RemoteAddr = "100.64.0.1:1234"
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						if mode == "service" && auth != "anonymous" {
							r.RemoteAddr = "127.0.0.1:1234"
							r.Header.Set("Tailscale-User-Login", profile.LoginName)
							r.Header.Set("X-Forwarded-For", "100.64.0.1")
						}
						switch auth {
						case "none":
							r.Header.Set("Origin", "https://attacker.example")
							r.Header.Set("Sec-Fetch-Site", "cross-site")
						case "header":
							r.Header.Set(secHeaderName, "test")
						case "anonymous":
							r.RemoteAddr = "192.0.2.1:1234"
						}
						w := httptest.NewRecorder()
						s.Handler().ServeHTTP(w, r)
						return w
					}
					if operation == "update" {
						seedAuth := "header"
						if auth == "anonymous" {
							seedAuth = auth
						}
						if w := post("https://before.example/", seedAuth); w.Code != http.StatusOK {
							t.Fatalf("seed: %d %s", w.Code, w.Body)
						}
					}
					before, _ := db.Load("protected")
					w := post("https://after.example/", auth)
					wantStatus := http.StatusOK
					if auth == "none" {
						wantStatus = http.StatusBadRequest
					} else if auth == "home-token" && operation == "update" {
						wantStatus = http.StatusSeeOther
					}
					if w.Code != wantStatus {
						t.Errorf("save: %d %s; want %d", w.Code, w.Body, wantStatus)
					}
					after, err := db.Load("protected")
					if wantStatus != http.StatusOK {
						if operation == "create" && !errors.Is(err, fs.ErrNotExist) {
							t.Errorf("rejected create persisted: %+v, %v", after, err)
						}
						if operation == "update" && (err != nil || !cmp.Equal(before, after)) {
							t.Errorf("rejected update changed data: %s, %v", cmp.Diff(before, after), err)
						}
					} else if err != nil || after.Long != "https://after.example/" {
						t.Errorf("permitted save missing: %+v, %v", after, err)
					}
				})
			}
		}
	}
}
