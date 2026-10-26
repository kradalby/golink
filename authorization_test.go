// Copyright 2026 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

package golink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

type authorizationGateReader struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *authorizationGateReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.Reader.Read(p)
}

func TestConcurrentOwnershipChanges(t *testing.T) {
	for _, operation := range []string{"save", "delete", "create"} {
		t.Run(operation, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			var pauseStatus atomic.Bool
			profiles := map[tailcfg.UserID]tailcfg.UserProfile{
				101: {ID: 101, LoginName: "alice@example.com"},
				202: {ID: 202, LoginName: "bob@example.com"},
				303: {ID: 303, LoginName: "admin@example.com"},
			}
			lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/localapi/v0/whois":
					id := tailcfg.UserID(101)
					if r.URL.Query().Get("addr") == "100.64.0.2:1234" {
						id = 202
					} else if r.URL.Query().Get("addr") == "100.64.0.3:1234" {
						id = 303
					}
					profile := profiles[id]
					whois := apitype.WhoIsResponse{Node: &tailcfg.Node{User: id}, UserProfile: &profile}
					if id == 303 {
						whois.CapMap = tailcfg.PeerCapMap{peerCapName: {tailcfg.RawMessage(`{"admin":true}`)}}
					}
					json.NewEncoder(w).Encode(whois)
				case "/localapi/v0/status":
					if pauseStatus.CompareAndSwap(true, false) {
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					json.NewEncoder(w).Encode(ipnstate.Status{
						CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"}, User: profiles,
					})
				case "/localapi/v0/prefs":
					json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
				default:
					http.NotFound(w, r)
				}
			}))
			db, err := NewSQLiteDB(filepath.Join(t.TempDir(), "links.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.db.Close() })
			s, err := New(Options{DB: db, LocalClient: lc})
			if err != nil {
				t.Fatal(err)
			}
			post := func(addr, path string, data url.Values, gate bool) *httptest.ResponseRecorder {
				var body io.Reader = strings.NewReader(data.Encode())
				if gate {
					body = &authorizationGateReader{Reader: body, entered: entered, release: release}
				}
				r := httptest.NewRequest("POST", "http://go"+path, body)
				r.RemoteAddr = addr
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set(secHeaderName, "test")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				return w
			}
			if operation != "create" {
				w := post("100.64.0.1:1234", "/", url.Values{"short": {"owned"}, "long": {"https://original.example/"}}, false)
				if w.Code != http.StatusOK {
					t.Fatalf("seed: %d %s", w.Code, w.Body)
				}
			}
			pauseStatus.Store(operation != "delete")
			done := make(chan *httptest.ResponseRecorder, 1)
			t.Cleanup(func() { unblock.Do(func() { close(release) }) })
			go func() {
				path := "/"
				data := url.Values{"short": {"owned"}, "long": {"https://stale.example/"}, "owner": {"alice@example.com"}}
				if operation == "delete" {
					path = "/.delete/owned"
					data = url.Values{"xsrf": {xsrftoken.Generate(s.xsrfKey, "alice@example.com", "owned")}}
				}
				done <- post("100.64.0.1:1234", path, data, operation == "delete")
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach the post-authorization gate")
			}
			w := post("100.64.0.3:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://transferred.example/"}, "owner": {"bob@example.com"},
			}, false)
			if w.Code != http.StatusOK {
				t.Fatalf("concurrent assignment: %d %s", w.Code, w.Body)
			}
			before, err := db.Load("owned")
			if err != nil || before.Owner != "bob@example.com" {
				t.Fatalf("concurrent owner missing: %v, %v", before, err)
			}
			unblock.Do(func() { close(release) })
			select {
			case w := <-done:
				if w.Code != http.StatusConflict {
					t.Errorf("stale %s: %d; want 409", operation, w.Code)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stale request did not finish")
			}
			after, err := db.Load("owned")
			if err != nil || !cmp.Equal(before, after) {
				t.Errorf("stale %s changed transferred link: %s, %v", operation, cmp.Diff(before, after), err)
			}
		})
	}
}
