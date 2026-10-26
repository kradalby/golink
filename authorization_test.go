// Copyright 2026 Tailscale Inc & Contributors
// SPDX-License-Identifier: BSD-3-Clause

package golink

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/html"
	"golang.org/x/net/xsrftoken"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
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

func detailForm(t *testing.T, s *Server, addr, short string) url.Values {
	t.Helper()
	r := httptest.NewRequest("GET", "http://go/.detail/"+short, nil)
	r.RemoteAddr = addr
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("detail form: %d %s", w.Code, w.Body)
	}
	doc, err := html.Parse(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				} else if a.Key == "value" {
					value = a.Val
				}
			}
			if name != "" {
				values.Set(name, value)
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	if values.Get("xsrf") == "" || values.Get("short") != short {
		t.Fatalf("missing editable form: %v", values)
	}
	return values
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
							data.Set("xsrf", xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/101`, scope))
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

func TestCSRFSeparatesSameLoginPrincipals(t *testing.T) {
	for _, kind := range []string{"person", "tagged"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestServer(t)
			s.currentUser = func(r *http.Request) (user, error) {
				u := user{login: "shared-label", ownerID: r.RemoteAddr, isAuthenticated: true}
				if kind == "tagged" {
					u.ownerID, u.nodeID = taggedOwnerID, r.RemoteAddr
				}
				return u, nil
			}
			r := httptest.NewRequest("GET", "http://go/", nil)
			r.RemoteAddr = "principal-one"
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			match := regexp.MustCompile(`name="xsrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
			if len(match) != 2 {
				t.Fatal("home form token missing")
			}
			for _, principal := range []string{"principal-two", "principal-one"} {
				r := httptest.NewRequest("POST", "http://go/", strings.NewReader(url.Values{
					"short": {"new-link"}, "long": {"https://example.com/"}, "xsrf": {match[1]},
				}.Encode()))
				r.RemoteAddr = principal
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				want := http.StatusBadRequest
				if principal == "principal-one" {
					want = http.StatusOK
				}
				if w.Code != want {
					t.Errorf("token used by %s: %d; want %d", principal, w.Code, want)
				}
			}
		})
	}
}

func TestConfiguredScopeStaysAuthoritative(t *testing.T) {
	var mu sync.Mutex
	reported := tailcfg.StableTailnetID("")
	profile := &tailcfg.UserProfile{ID: 101, LoginName: "alice"}
	lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/localapi/v0/whois":
			json.NewEncoder(w).Encode(apitype.WhoIsResponse{Node: &tailcfg.Node{User: profile.ID}, UserProfile: profile})
		case "/localapi/v0/status":
			json.NewEncoder(w).Encode(ipnstate.Status{CurrentTailnet: &ipnstate.TailnetStatus{StableID: reported}})
		case "/localapi/v0/prefs":
			json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
		}
	}))
	db, err := NewSQLiteDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.db.Close() })
	s, err := New(Options{DB: db, LocalClient: lc, IdentityScope: "operator-scope"})
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"configured", "reported-too", "configured-removed"} {
		mu.Lock()
		if phase != "configured" {
			reported = "operator-scope"
		}
		mu.Unlock()
		if phase == "configured-removed" {
			s.identityScope = ""
		}
		r := httptest.NewRequest("POST", "http://go/", strings.NewReader("short=owned&long=https://example.com/"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(secHeaderName, "test")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := http.StatusOK
		if phase == "configured-removed" {
			want = http.StatusForbidden
		}
		if w.Code != want {
			t.Errorf("%s: %d %s; want %d", phase, w.Code, w.Body, want)
		}
	}
}

func TestSnapshotKeepsExistingOwnership(t *testing.T) {
	s := newTestServer(t)
	want := &Link{Short: "kept", Long: "https://original.example/", Owner: "owner", OwnerID: "bound-owner", Created: time.Unix(100, 0).UTC(), LastEdit: time.Unix(200, 0).UTC()}
	if err := s.db.Save(want); err != nil {
		t.Fatal(err)
	}
	if err := s.db.SaveStats(ClickStats{"kept": 7}); err != nil {
		t.Fatal(err)
	}
	snapshot := []byte(`{"Short":"kept","Long":"https://old.example/","Owner":"reused-label"}
{"Short":"new","Long":"https://new.example/","Owner":"owner","OwnerID":"bound-new"}
{"Short":"new","Long":"https://duplicate.example/","Owner":"reused-label"}`)
	for range 2 {
		if err := s.restoreSnapshot(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.db.Load("kept")
	if err != nil || !cmp.Equal(want, got) {
		t.Fatalf("restore changed existing link: %s, %v", cmp.Diff(want, got), err)
	}
	got, err = s.db.Load("new")
	if err != nil || got.OwnerID != "bound-new" || got.Long != "https://new.example/" {
		t.Fatalf("restore replaced inserted link: %v, %v", got, err)
	}
	stats, err := s.db.LoadStats()
	if err != nil || stats["kept"] != 7 {
		t.Errorf("restore changed stats: %v, %v", stats, err)
	}
}

func TestOwnershipSurvivesLoginReuse(t *testing.T) {
	var mu sync.RWMutex
	profiles := map[string]tailcfg.UserProfile{
		"100.64.0.1:1234": {ID: 101, LoginName: "alice@example.com"},
	}
	lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		switch r.URL.Path {
		case "/localapi/v0/whois":
			profile, ok := profiles[r.URL.Query().Get("addr")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(apitype.WhoIsResponse{
				Node: &tailcfg.Node{User: profile.ID}, UserProfile: &profile,
			})
		case "/localapi/v0/status":
			users := make(map[tailcfg.UserID]tailcfg.UserProfile)
			peers := make(map[key.NodePublic]*ipnstate.PeerStatus)
			for _, p := range profiles {
				users[p.ID] = p
				peers[key.NewNode().Public()] = &ipnstate.PeerStatus{UserID: p.ID}
			}
			json.NewEncoder(w).Encode(ipnstate.Status{
				CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"}, User: users, Peer: peers,
			})
		case "/localapi/v0/prefs":
			json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
		default:
			http.NotFound(w, r)
		}
	}))
	open := func(path string) *Server {
		t.Helper()
		db, err := NewSQLiteDB(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.db.Close() })
		s, err := New(Options{DB: db, LocalClient: lc})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	path := filepath.Join(t.TempDir(), "links.db")
	s := open(path)
	post := func(addr, path string, data url.Values, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "http://go"+path, strings.NewReader(data.Encode()))
		r.RemoteAddr = addr
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if data.Get("xsrf") == "" {
			r.Header.Set(secHeaderName, "test")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s %s: %d; want %d", addr, path, w.Code, want)
		}
	}
	for _, short := range []string{"owned", "delete-protected"} {
		post("100.64.0.1:1234", "/", url.Values{
			"short": {short}, "long": {"https://original.example/"},
		}, http.StatusOK)
	}
	initial, err := s.db.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.SaveStats(ClickStats{"owned": 7}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	profiles["100.64.0.1:1234"] = tailcfg.UserProfile{ID: 101, LoginName: "renamed@example.com"}
	profiles["100.64.0.2:1234"] = tailcfg.UserProfile{ID: 202, LoginName: "alice@example.com"}
	mu.Unlock()
	first := detailForm(t, s, "100.64.0.1:1234", "owned")
	stale := detailForm(t, s, "100.64.0.1:1234", "owned")
	if first.Get("owner") != "alice@example.com" || stale.Get("owner") != first.Get("owner") {
		t.Fatalf("expected two old-label forms after rename: %v %v", first, stale)
	}
	post("100.64.0.1:1234", "/", first, http.StatusOK)
	renamed, err := s.db.Load("owned")
	if err != nil || renamed.Owner != "renamed@example.com" {
		t.Fatalf("first form did not refresh the display label: %v, %v", renamed, err)
	}
	post("100.64.0.1:1234", "/", stale, http.StatusOK)
	stillOwned, err := s.db.Load("owned")
	if err != nil || stillOwned.OwnerID != renamed.OwnerID || stillOwned.Owner != renamed.Owner {
		t.Fatalf("stale form changed ownership: %v, %v", stillOwned, err)
	}
	initial, err = s.db.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"live", "reopened", "restored"} {
		t.Run(phase, func(t *testing.T) {
			// A failed attack in one phase must not destroy the next phase's fixture.
			for _, link := range initial {
				if err := s.db.Save(link); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "reopened" {
				if err := s.db.db.Close(); err != nil {
					t.Fatal(err)
				}
				s = open(path)
			} else if phase == "restored" {
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://go/.export", nil))
				if w.Code != http.StatusOK {
					t.Fatal(w.Body.String())
				}
				s = open(filepath.Join(t.TempDir(), "restored.db"))
				if err := s.restoreSnapshot(w.Body.Bytes()); err != nil {
					t.Fatal(err)
				}
			}
			for _, link := range initial {
				got, err := s.db.Load(link.Short)
				if err != nil || !cmp.Equal(got, link) {
					t.Fatalf("metadata lost during %s: %s, %v", phase, cmp.Diff(link, got), err)
				}
			}
			if phase != "restored" {
				stats, err := s.db.LoadStats()
				if err != nil || stats["owned"] != 7 {
					t.Fatalf("stats lost during %s: %v, %v", phase, stats, err)
				}
			}
			post("100.64.0.2:1234", "/", url.Values{
				"short": {"newcomer-control"}, "long": {"https://newcomer.example/"},
			}, http.StatusOK)
			post("100.64.0.2:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://attacker.example/"},
			}, http.StatusForbidden)
			post("100.64.0.2:1234", "/.delete/delete-protected", url.Values{
				"xsrf": {xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/202`, "delete-protected")},
			}, http.StatusForbidden)
			post("100.64.0.1:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://original.example/"}, "owner": {"alice@example.com"},
			}, http.StatusOK)
			post("100.64.0.2:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://attacker.example/"},
			}, http.StatusForbidden)
			for _, short := range []string{"owned", "delete-protected"} {
				link, err := s.db.Load(short)
				if err != nil || link.Long != "https://original.example/" {
					t.Errorf("original link lost: %+v, %v", link, err)
				}
			}
			post("100.64.0.1:1234", "/.delete/delete-protected", url.Values{
				"xsrf": {xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/101`, "delete-protected")},
			}, http.StatusOK)
			post("100.64.0.1:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://transferred.example/"}, "action": {"transfer"},
				"owner-id": {`["https://control.example","reported","test-tailnet"]/202`},
			}, http.StatusOK)
			post("100.64.0.1:1234", "/", url.Values{"short": {"owned"}, "long": {"https://denied.example/"}}, http.StatusForbidden)
			post("100.64.0.2:1234", "/", url.Values{"short": {"owned"}, "long": {"https://new-owner.example/"}}, http.StatusOK)
		})
	}
}

func TestOwnershipIdentityBoundaries(t *testing.T) {
	for _, change := range []string{"different-user", "different-issuer", "different-tailnet", "missing-tailnet", "missing-user-id", "empty-owner-label", "tagged-node", "header-only"} {
		t.Run(change, func(t *testing.T) {
			var mu sync.Mutex
			profile := tailcfg.UserProfile{ID: 101, LoginName: "tagged-devices"}
			issuer, scope := "https://control.example", "test-tailnet"
			var tags []string
			lookupFails := false
			lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/localapi/v0/whois":
					if lookupFails {
						http.NotFound(w, r)
						return
					}
					json.NewEncoder(w).Encode(apitype.WhoIsResponse{
						Node: &tailcfg.Node{User: profile.ID, Tags: tags}, UserProfile: &profile,
					})
				case "/localapi/v0/status":
					json.NewEncoder(w).Encode(ipnstate.Status{
						CurrentTailnet: &ipnstate.TailnetStatus{StableID: tailcfg.StableTailnetID(scope)},
						User:           map[tailcfg.UserID]tailcfg.UserProfile{profile.ID: profile},
					})
				case "/localapi/v0/prefs":
					json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: issuer})
				default:
					http.NotFound(w, r)
				}
			}))
			db, err := NewSQLiteDB(filepath.Join(t.TempDir(), "links.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.db.Close() })
			s, err := New(Options{DB: db, LocalClient: lc, AllowUnknownUsers: true})
			if err != nil {
				t.Fatal(err)
			}
			post := func(path string, data url.Values, want int) {
				t.Helper()
				r := httptest.NewRequest("POST", "http://go"+path, strings.NewReader(data.Encode()))
				r.RemoteAddr = "100.64.0.1:1234"
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set(secHeaderName, "test")
				if s.serviceName != "" {
					r.RemoteAddr = "127.0.0.1:1234"
					r.Header.Set("Tailscale-User-Login", profile.LoginName)
					r.Header.Set("X-Forwarded-For", "100.64.0.1")
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != want {
					t.Errorf("%s: %d; want %d", path, w.Code, want)
				}
			}
			post("/", url.Values{"short": {"owned"}, "long": {"https://original.example/"}}, http.StatusOK)
			before, err := db.Load("owned")
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			switch change {
			case "different-user":
				profile.ID = 202
			case "different-issuer":
				issuer = "https://other-control.example"
			case "different-tailnet":
				scope = "other-tailnet"
			case "missing-tailnet":
				scope = ""
			case "missing-user-id":
				profile.ID = 0
			case "empty-owner-label":
				before.Owner = ""
				if err := db.Save(before); err != nil {
					t.Fatal(err)
				}
				profile.ID = 202
			case "tagged-node":
				tags = []string{"tag:client"}
			case "header-only":
				s.serviceName = "svc:golink"
				lookupFails = true
			}
			mu.Unlock()
			post("/", url.Values{"short": {"owned"}, "long": {"https://attacker.example/"}}, http.StatusForbidden)
			post("/.delete/owned", url.Values{
				"xsrf": {xsrftoken.Generate(s.xsrfKey, profile.LoginName, "owned")},
			}, http.StatusForbidden)
			after, err := db.Load("owned")
			if err != nil || !cmp.Equal(before, after) {
				t.Errorf("identity change granted mutation: %s, %v", cmp.Diff(before, after), err)
			}
			if change == "missing-tailnet" || change == "missing-user-id" || change == "header-only" {
				post("/", url.Values{"short": {"new"}, "long": {"https://example.com/"}}, http.StatusForbidden)
				if _, err := db.Load("new"); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("unbound creation persisted: %v", err)
				}
			}
		})
	}
}

func TestTransferRejectsTaggedPrincipals(t *testing.T) {
	for _, location := range []string{"self", "peer", "cached", "untagged-self"} {
		t.Run(location, func(t *testing.T) {
			profiles := map[tailcfg.UserID]tailcfg.UserProfile{
				101: {ID: 101, LoginName: "alice"},
				202: {ID: 202, LoginName: "tagged-devices"},
				909: {ID: 909, LoginName: "tagged-devices"},
			}
			tags := views.SliceOf([]string{"tag:client"})
			untaggedKey := key.NewNode().Public()
			status := ipnstate.Status{
				CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"},
				User:           profiles,
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					untaggedKey:            {UserID: 202},
					key.NewNode().Public(): {UserID: 202, Tags: &tags},
				},
			}
			tagged := &ipnstate.PeerStatus{UserID: 909, Tags: &tags}
			if location == "self" {
				status.Self = tagged
			} else if location != "cached" {
				status.Peer[key.NewNode().Public()] = tagged
			}
			if location == "cached" {
				status.Self = &ipnstate.PeerStatus{UserID: 101}
			} else if location == "untagged-self" {
				status.Self = &ipnstate.PeerStatus{UserID: 202}
				delete(status.Peer, untaggedKey)
			}
			lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/localapi/v0/whois":
					profile := profiles[101]
					if r.URL.Query().Get("addr") == "100.64.0.2:1234" {
						profile = profiles[202]
					}
					json.NewEncoder(w).Encode(apitype.WhoIsResponse{Node: &tailcfg.Node{User: profile.ID}, UserProfile: &profile})
				case "/localapi/v0/status":
					json.NewEncoder(w).Encode(status)
				case "/localapi/v0/prefs":
					json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
				default:
					http.NotFound(w, r)
				}
			}))
			db, err := NewSQLiteDB(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.db.Close() })
			s, err := New(Options{DB: db, LocalClient: lc})
			if err != nil {
				t.Fatal(err)
			}
			post := func(addr, target string, want int) {
				t.Helper()
				data := url.Values{"short": {"owned"}, "long": {"https://example.com/"}}
				if target != "" {
					data.Set("action", "transfer")
					data.Set("owner-id", `["https://control.example","reported","test-tailnet"]/`+target)
				}
				r := httptest.NewRequest("POST", "http://go/", strings.NewReader(data.Encode()))
				r.RemoteAddr = addr
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set(secHeaderName, "test")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != want {
					t.Errorf("transfer to %q: %d %s; want %d", target, w.Code, w.Body, want)
				}
			}
			post("100.64.0.1:1234", "", http.StatusOK)
			before, err := db.Load("owned")
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "http://go/.detail/owned", nil)
			r.RemoteAddr = "100.64.0.1:1234"
			r.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "user ID 909)") || !strings.Contains(w.Body.String(), "tagged-devices (user ID 202)") {
				t.Errorf("transfer choices must exclude tagged principal and retain same-label person: %d %s", w.Code, w.Body)
			}
			post("100.64.0.1:1234", "909", http.StatusBadRequest)
			after, err := db.Load("owned")
			if err != nil || !cmp.Equal(before, after) {
				t.Fatalf("rejected tagged transfer changed link: %s, %v", cmp.Diff(before, after), err)
			}
			post("100.64.0.1:1234", "202", http.StatusOK)
			post("100.64.0.1:1234", "", http.StatusForbidden)
			post("100.64.0.2:1234", "", http.StatusOK)
			after, err = db.Load("owned")
			if err != nil || after.Owner != "tagged-devices" || after.OwnerID != `["https://control.example","reported","test-tailnet"]/202` {
				t.Fatalf("same-label person lost immutable ownership: %v, %v", after, err)
			}
		})
	}
}

func TestTransferRejectsDuplicateLogin(t *testing.T) {
	profiles := map[tailcfg.UserID]tailcfg.UserProfile{
		101: {ID: 101, LoginName: "alice@example.com"},
		202: {ID: 202, LoginName: "duplicate@example.com"},
		303: {ID: 303, LoginName: "duplicate@example.com"},
	}
	lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/whois":
			profile := profiles[101]
			json.NewEncoder(w).Encode(apitype.WhoIsResponse{
				Node: &tailcfg.Node{User: profile.ID}, UserProfile: &profile,
			})
		case "/localapi/v0/status":
			json.NewEncoder(w).Encode(ipnstate.Status{
				CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"}, User: profiles,
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {UserID: 202},
					key.NewNode().Public(): {UserID: 303},
				},
			})
		case "/localapi/v0/prefs":
			json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
		default:
			http.NotFound(w, r)
		}
	}))
	db, err := NewSQLiteDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.db.Close() })
	s, err := New(Options{DB: db, LocalClient: lc})
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"", "duplicate@example.com"} {
		before, _ := db.Load("owned")
		r := httptest.NewRequest("POST", "http://go/", strings.NewReader(url.Values{
			"short": {"owned"}, "long": {"https://original.example/"}, "owner": {owner},
		}.Encode()))
		r.RemoteAddr = "100.64.0.1:1234"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(secHeaderName, "test")
		if owner != "" {
			r.URL.RawQuery = "action=transfer"
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := http.StatusOK
		if owner != "" {
			want = http.StatusBadRequest
			got, err := db.Load("owned")
			if err != nil || !cmp.Equal(got, before) {
				t.Errorf("ambiguous transfer changed link: %s, %v", cmp.Diff(before, got), err)
			}
		}
		if w.Code != want {
			t.Errorf("owner %q: %d; want %d", owner, w.Code, want)
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
			var statusCalls atomic.Int32
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
					// Scope lookup precedes authorization; target lookup follows it.
					if pauseStatus.Load() && statusCalls.Add(1) == 2 && pauseStatus.CompareAndSwap(true, false) {
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					json.NewEncoder(w).Encode(ipnstate.Status{
						CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"}, User: profiles,
						Peer: map[key.NodePublic]*ipnstate.PeerStatus{
							key.NewNode().Public(): {UserID: 101},
							key.NewNode().Public(): {UserID: 202},
						},
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
				data := url.Values{"short": {"owned"}, "long": {"https://stale.example/"}, "action": {"transfer"}, "owner-id": {`["https://control.example","reported","test-tailnet"]/101`}}
				if operation == "delete" {
					path = "/.delete/owned"
					data = url.Values{"xsrf": {xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/101`, "owned")}}
				}
				done <- post("100.64.0.1:1234", path, data, operation == "delete")
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach the post-authorization gate")
			}
			w := post("100.64.0.3:1234", "/", url.Values{
				"short": {"owned"}, "long": {"https://transferred.example/"}, "action": {"transfer"}, "owner-id": {`["https://control.example","reported","test-tailnet"]/202`},
			}, false)
			if w.Code != http.StatusOK {
				t.Fatalf("concurrent assignment: %d %s", w.Code, w.Body)
			}
			before, err := db.Load("owned")
			if err != nil || before.Owner != "bob@example.com" {
				t.Fatalf("concurrent owner missing: %v, %v", before, err)
			}
			if err := db.SaveStats(ClickStats{"owned": 7}); err != nil {
				t.Fatal(err)
			}
			if err := s.initStats(); err != nil {
				t.Fatal(err)
			}
			s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://go/owned", nil))
			registry := prometheus.NewRegistry()
			registry.MustRegister(totalLinkCount)
			metricBefore, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
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
			stats, err := db.LoadStats()
			if err != nil || stats["owned"] != 7 || s.stats.clicks["owned"] != 8 || s.stats.dirty["owned"] != 1 {
				t.Errorf("conflict changed stats: %v, %v; memory=%v pending=%v", stats, err, s.stats.clicks, s.stats.dirty)
			}
			metricAfter, err := registry.Gather()
			if err != nil || metricBefore[0].Metric[0].GetGauge().GetValue() != metricAfter[0].Metric[0].GetGauge().GetValue() {
				t.Errorf("conflict changed totalLinkCount: %v", err)
			}
			w = post("100.64.0.2:1234", "/", url.Values{"short": {"owned"}, "long": {"https://owner-control.example/"}}, false)
			if w.Code != http.StatusOK {
				t.Errorf("new owner control: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestLegacyOwnershipDoesNotBindReusedLogin(t *testing.T) {
	for _, source := range []string{"old-schema", "old-snapshot"} {
		for _, login := range []string{"alice@example.com", "tagged-devices"} {
			t.Run(source+"/"+login, func(t *testing.T) {
				// The rename and reuse predate opening the old data with the new server.
				profiles := map[tailcfg.UserID]tailcfg.UserProfile{
					101: {ID: 101, LoginName: "renamed@example.com"},
					202: {ID: 202, LoginName: login},
					303: {ID: 303, LoginName: "admin@example.com"},
				}
				lc := testLocalClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/localapi/v0/whois":
						profile := profiles[202]
						if r.URL.Query().Get("addr") == "100.64.0.3:1234" {
							profile = profiles[303]
						}
						whois := apitype.WhoIsResponse{
							Node: &tailcfg.Node{User: profile.ID}, UserProfile: &profile,
						}
						if profile.ID == 303 {
							whois.CapMap = tailcfg.PeerCapMap{peerCapName: {tailcfg.RawMessage(`{"admin":true}`)}}
						}
						json.NewEncoder(w).Encode(whois)
					case "/localapi/v0/status":
						json.NewEncoder(w).Encode(ipnstate.Status{
							CurrentTailnet: &ipnstate.TailnetStatus{StableID: "test-tailnet"}, User: profiles,
							Peer: map[key.NodePublic]*ipnstate.PeerStatus{
								key.NewNode().Public(): {UserID: 101},
							},
						})
					case "/localapi/v0/prefs":
						json.NewEncoder(w).Encode(ipn.Prefs{ControlURL: "https://control.example"})
					default:
						http.NotFound(w, r)
					}
				}))
				path := filepath.Join(t.TempDir(), "legacy.db")
				oldDB, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				// Keep the pre-binding schema literal so the migration is actually exercised.
				_, err = oldDB.Exec(`CREATE TABLE Links (
					ID TEXT PRIMARY KEY, Short TEXT NOT NULL DEFAULT '', Long TEXT NOT NULL DEFAULT '',
					Created INTEGER NOT NULL, LastEdit INTEGER NOT NULL, Owner TEXT NOT NULL DEFAULT '');
					CREATE TABLE Stats (ID TEXT NOT NULL, Created INTEGER NOT NULL, Clicks INTEGER);
					INSERT INTO Stats VALUES ('legacy', 1654131723, 7);`)
				if err != nil {
					t.Fatal(err)
				}
				if source == "old-schema" {
					_, err = oldDB.Exec(`INSERT INTO Links VALUES ('legacy', 'legacy', 'https://original.example/', 1654131723, 1654131903, ?)`, login)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := oldDB.Close(); err != nil {
					t.Fatal(err)
				}
				db, err := NewSQLiteDB(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.db.Close() })
				s, err := New(Options{DB: db, LocalClient: lc})
				if err != nil {
					t.Fatal(err)
				}
				if source == "old-snapshot" {
					snapshot := fmt.Sprintf(`{"Short":"legacy","Long":"https://original.example/","Created":"2022-06-02T01:02:03Z","LastEdit":"2022-06-02T01:05:03Z","Owner":%q}`, login)
					if err := s.restoreSnapshot([]byte(snapshot)); err != nil {
						t.Fatal(err)
					}
				}
				want := &Link{
					Short: "legacy", Long: "https://original.example/", Owner: login,
					Created: time.Unix(1654131723, 0).UTC(), LastEdit: time.Unix(1654131903, 0).UTC(),
				}
				check := func() {
					t.Helper()
					got, err := db.Load("legacy")
					if err != nil || !cmp.Equal(got, want) {
						t.Errorf("legacy metadata changed: %s, %v", cmp.Diff(want, got), err)
					}
					var created, clicks int64
					err = db.db.QueryRow("SELECT Created, Clicks FROM Stats WHERE ID = 'legacy'").Scan(&created, &clicks)
					if err != nil || created != 1654131723 || clicks != 7 {
						t.Errorf("legacy stats changed: %d, %d, %v", created, clicks, err)
					}
				}
				check()
				for _, operation := range []string{"update", "delete"} {
					path := "/"
					data := url.Values{"short": {"legacy"}, "long": {"https://attacker.example/"}}
					if operation == "delete" {
						path = "/.delete/legacy"
						data.Set("xsrf", xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/202`, "legacy"))
					}
					r := httptest.NewRequest("POST", "http://go"+path, strings.NewReader(data.Encode()))
					r.RemoteAddr = "100.64.0.2:1234"
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					r.Header.Set(secHeaderName, "test")
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, r)
					if w.Code != http.StatusForbidden {
						t.Errorf("legacy %s by reused login: %d; want 403", operation, w.Code)
					}
					check()
				}
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "http://go/legacy", nil)
				r.RemoteAddr = "100.64.0.2:1234"
				s.Handler().ServeHTTP(w, r)
				if w.Code != http.StatusFound || w.Header().Get("Location") != want.Long {
					t.Errorf("legacy link no longer resolves: %d %q", w.Code, w.Header().Get("Location"))
				}
				for _, action := range []string{"update", "delete", "transfer"} {
					path := "/"
					data := url.Values{"short": {"legacy"}, "long": {want.Long}, "owner": {login}}
					status := http.StatusForbidden
					if action == "delete" {
						path = "/.delete/legacy"
						data.Set("xsrf", xsrftoken.Generate(s.xsrfKey, `["https://control.example","reported","test-tailnet"]/303`, "legacy"))
					} else if action == "transfer" {
						data.Set("action", "transfer")
						data.Set("owner-id", `["https://control.example","reported","test-tailnet"]/101`)
						status = http.StatusOK
					}
					r := httptest.NewRequest("POST", "http://go"+path, strings.NewReader(data.Encode()))
					r.RemoteAddr = "100.64.0.3:1234"
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					r.Header.Set(secHeaderName, "test")
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, r)
					if w.Code != status {
						t.Errorf("legacy admin %s: %d %s; want %d", action, w.Code, w.Body, status)
					}
					if action != "transfer" {
						check()
					}
				}
				recovered, err := db.Load("legacy")
				if err != nil || recovered.OwnerID != `["https://control.example","reported","test-tailnet"]/101` || recovered.Owner != "renamed@example.com" || recovered.Long != want.Long || !recovered.Created.Equal(want.Created) {
					t.Fatalf("explicit recovery lost data or selected reused login: %v, %v", recovered, err)
				}
				stats, err := db.LoadStats()
				if err != nil || stats["legacy"] != 7 {
					t.Errorf("recovery changed stats: %v, %v", stats, err)
				}
			})
		}
	}
}
