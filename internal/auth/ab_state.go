package auth

import (
    "net/http"
    "os"

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
    authKey := []byte(os.Getenv("SESSION_AUTH_KEY"))
    encKey := []byte(os.Getenv("SESSION_ENC_KEY"))
    if len(authKey) == 0 {
        authKey = securecookie.GenerateRandomKey(32)
    }
    if len(encKey) == 0 {
        encKey = securecookie.GenerateRandomKey(32)
    }
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
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    if !c.Persistent {
        ck.MaxAge = 0
    } else {
        ck.MaxAge = 60 * 60 * 24 * 30
    }
    http.SetCookie(w, ck)
    return nil
}
