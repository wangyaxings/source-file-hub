package authz

import (
    "fmt"
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

// CheckPermission checks if a subject has permission to perform an action on an object
func CheckPermission(subject, object, action string) (bool, error) {
    e := GetEnforcer()
    if e == nil {
        return false, fmt.Errorf("enforcer not initialized")
    }
    return e.Enforce(subject, object, action)
}

// CheckResourcePermission checks resource-specific permissions
func CheckResourcePermission(subject, resource, action string) (bool, error) {
    return CheckPermission(subject, resource, action)
}

// AddPolicy adds a policy rule
func AddPolicy(subject, object, action string) (bool, error) {
    e := GetEnforcer()
    if e == nil {
        return false, fmt.Errorf("enforcer not initialized")
    }
    return e.AddPolicy(subject, object, action)
}

// RemovePolicy removes a policy rule
func RemovePolicy(subject, object, action string) (bool, error) {
    e := GetEnforcer()
    if e == nil {
        return false, fmt.Errorf("enforcer not initialized")
    }
    return e.RemovePolicy(subject, object, action)
}

// GetPolicies gets all policy rules
func GetPolicies() [][]string {
    e := GetEnforcer()
    if e == nil {
        return nil
    }
    return e.GetPolicy()
}

// GetPoliciesForSubject gets policies for a specific subject
func GetPoliciesForSubject(subject string) [][]string {
    e := GetEnforcer()
    if e == nil {
        return nil
    }
    return e.GetFilteredPolicy(0, subject)
}

// GetPoliciesForObject gets policies for a specific object
func GetPoliciesForObject(object string) [][]string {
    e := GetEnforcer()
    if e == nil {
        return nil
    }
    return e.GetFilteredPolicy(1, object)
}

// GetPoliciesForAction gets policies for a specific action
func GetPoliciesForAction(action string) [][]string {
    e := GetEnforcer()
    if e == nil {
        return nil
    }
    return e.GetFilteredPolicy(2, action)
}

// LoadPolicy loads policy from file
func LoadPolicy() error {
    e := GetEnforcer()
    if e == nil {
        return fmt.Errorf("enforcer not initialized")
    }
    return e.LoadPolicy()
}

// SavePolicy saves policy to file
func SavePolicy() error {
    e := GetEnforcer()
    if e == nil {
        return fmt.Errorf("enforcer not initialized")
    }
    return e.SavePolicy()
}

// GetRolesForUser gets roles for a user
func GetRolesForUser(user string) ([]string, error) {
    e := GetEnforcer()
    if e == nil {
        return nil, fmt.Errorf("enforcer not initialized")
    }
    return e.GetRolesForUser(user)
}

// GetUsersForRole gets users for a role
func GetUsersForRole(role string) ([]string, error) {
    e := GetEnforcer()
    if e == nil {
        return nil, fmt.Errorf("enforcer not initialized")
    }
    return e.GetUsersForRole(role)
}

// AddRoleForUser adds a role for a user
func AddRoleForUser(user, role string) (bool, error) {
    e := GetEnforcer()
    if e == nil {
        return false, fmt.Errorf("enforcer not initialized")
    }
    return e.AddRoleForUser(user, role)
}

// DeleteRoleForUser deletes a role for a user
func DeleteRoleForUser(user, role string) (bool, error) {
    e := GetEnforcer()
    if e == nil {
        return false, fmt.Errorf("enforcer not initialized")
    }
    return e.DeleteRoleForUser(user, role)
}

