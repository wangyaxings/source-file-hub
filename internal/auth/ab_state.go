package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	ab "github.com/aarondl/authboss/v3"
	"github.com/gorilla/securecookie"
)

// simpleState implements authboss.ClientState using a map
type simpleState map[string]string

func (s simpleState) Get(key string) (string, bool) {
	v, ok := s[key]
	return v, ok
}

// cookieStateRW implements ClientStateReadWriter using gorilla/securecookie
type cookieStateRW struct {
	CookieName string
	Persistent bool
	sc         *securecookie.SecureCookie
}

func newCookieStateRW(name string, persistent bool) cookieStateRW {
	authKey, encKey := loadCookieKeys()
	sc := securecookie.New(authKey, encKey)
	sc.SetSerializer(securecookie.JSONEncoder{})
	return cookieStateRW{CookieName: name, Persistent: persistent, sc: sc}
}

func (c cookieStateRW) ReadState(r *http.Request) (ab.ClientState, error) {
	ck, err := r.Cookie(c.CookieName)
	if err != nil || ck == nil {
		return simpleState{}, nil
	}
	m := map[string]string{}
	if err := c.sc.Decode(c.CookieName, ck.Value, &m); err != nil {
		return simpleState{}, nil
	}
	return simpleState(m), nil
}

func (c cookieStateRW) WriteState(w http.ResponseWriter, state ab.ClientState, events []ab.ClientStateEvent) error {
	s, _ := state.(simpleState)
	if s == nil {
		s = simpleState{}
	}
	for _, ev := range events {
		switch ev.Kind {
		case ab.ClientStateEventPut:
			s[ev.Key] = ev.Value
		case ab.ClientStateEventDel:
			delete(s, ev.Key)
		case ab.ClientStateEventDelAll:
			for k := range s {
				delete(s, k)
			}
		}
	}

	encoded, err := c.sc.Encode(c.CookieName, map[string]string(s))
	if err != nil {
		return err
	}
	ck := &http.Cookie{
		Name:     c.CookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Allow non-HTTPS in development/testing
		SameSite: http.SameSiteLaxMode,
		Domain:   "", // 不设置域名，允许跨子域名访问
	}
	if !c.Persistent {
		ck.MaxAge = 0
	} else {
		ck.MaxAge = 60 * 60 * 24 * 30
	}
	http.SetCookie(w, ck)
	return nil
}

// -----------------------------------------------------------------------------
// Cookie Keys Loader
// -----------------------------------------------------------------------------

var (
	cookieKeysOnce sync.Once
	cachedAuthKey  []byte
	cachedEncKey   []byte
)

type sessionConfig struct {
	Session struct {
		AuthKey string `json:"auth_key"`
		EncKey  string `json:"enc_key"`
	} `json:"session"`
}

// loadCookieKeys loads securecookie keys from configs/config.json, then env vars, then random
func loadCookieKeys() ([]byte, []byte) {
	cookieKeysOnce.Do(func() {
		// 1) Try configs/config.json
		cfgPath := filepath.Join("configs", "config.json")
		if b, err := os.ReadFile(cfgPath); err == nil {
			var cfg sessionConfig
			if json.Unmarshal(b, &cfg) == nil {
				if cfg.Session.AuthKey != "" {
					cachedAuthKey = []byte(cfg.Session.AuthKey)
				}
				if cfg.Session.EncKey != "" {
					cachedEncKey = []byte(cfg.Session.EncKey)
				}
			}
		}

		// 2) Fallback to environment variables (backward compatible)
		envAuth := os.Getenv("SESSION_AUTH_KEY")
		envEnc := os.Getenv("SESSION_ENC_KEY")
		fromConfigAuth := len(cachedAuthKey) != 0
		fromConfigEnc := len(cachedEncKey) != 0
		if len(cachedAuthKey) == 0 && envAuth != "" {
			cachedAuthKey = []byte(envAuth)
		}
		if len(cachedEncKey) == 0 && envEnc != "" {
			cachedEncKey = []byte(envEnc)
		}

		// 3) Final fallback: generate random keys and log a warning
		if len(cachedAuthKey) == 0 {
			cachedAuthKey = securecookie.GenerateRandomKey(32)
		}
		if len(cachedEncKey) == 0 {
			cachedEncKey = securecookie.GenerateRandomKey(32)
		}

		// If either key came from random generation, emit a warning to stdout
		// to avoid unexpected session invalidation on restart.
		// We detect random by length check right after generation time window.
		// Note: This simple heuristic logs when keys were missing from config/env.
		if os.Getenv("SILENCE_COOKIE_KEY_WARN") == "" { // allow disabling in tests
			if !fromConfigAuth && !fromConfigEnc && envAuth == "" && envEnc == "" {
				// No env provided; if config also missing, warn.
				// We can't easily know config presence beyond our checks; log generic warning.
				log.Printf("[WARN] Secure cookie keys not set in configs/config.json (session.auth_key/enc_key) or env; generated random keys. Sessions may be invalidated after restart.")
			}
		}
	})
	return cachedAuthKey, cachedEncKey
}
