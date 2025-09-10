package authz

import (
    "log"
    "path/filepath"
    "sync"

    "github.com/casbin/casbin/v2"
    "github.com/casbin/casbin/v2/model"
    fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

var (
    enforcer *casbin.Enforcer
    once sync.Once
)

// GetEnforcer returns a singleton Casbin enforcer
func GetEnforcer() *casbin.Enforcer {
    once.Do(func() {
        // Load model and policy from configs
        m, err := model.NewModelFromFile(filepath.FromSlash("configs/casbin_model.conf"))
        if err != nil {
            log.Printf("casbin: failed to load model: %v", err)
            return
        }
        a := fileadapter.NewAdapter(filepath.FromSlash("configs/casbin_policy.csv"))
        e, err := casbin.NewEnforcer(m, a)
        if err != nil {
            log.Printf("casbin: failed to create enforcer: %v", err)
            return
        }
        if err := e.LoadPolicy(); err != nil {
            log.Printf("casbin: failed to load policy: %v", err)
        }
        enforcer = e
    })
    return enforcer
}

