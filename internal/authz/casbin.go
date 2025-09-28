package authz

import (
	"fmt"
	"log"
	"secure-file-hub/internal/database"
	"sync"

	"github.com/casbin/casbin/v2"
)

var (
	enforcer *casbin.Enforcer
	once     sync.Once
)

// GetEnforcer returns a singleton Casbin enforcer
func GetEnforcer() *casbin.Enforcer {
	once.Do(func() {
		// 直接使用数据库适配器
		if db := database.GetDatabase(); db != nil {
			if e, err := GetEnforcerWithDB(db.GetDB()); err == nil {
				enforcer = e
				log.Println("casbin: initialized with database adapter")
				return
			} else {
				log.Fatalf("casbin: failed to initialize with database adapter: %v", err)
			}
		} else {
			log.Fatal("casbin: database not initialized")
		}
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

// SavePolicy saves policy (数据库适配器自动处理，无需手动保存)
func SavePolicy() error {
	// 数据库适配器会自动持久化策略，无需手动保存
	return nil
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

// API Key specific functions

// AddAPIKeyPolicy adds a policy for an API key
func AddAPIKeyPolicy(apiKeyID, resource, action string) (bool, error) {
	return AddPolicy(apiKeyID, resource, action)
}

// RemoveAPIKeyPolicy removes a policy for an API key
func RemoveAPIKeyPolicy(apiKeyID, resource, action string) (bool, error) {
	return RemovePolicy(apiKeyID, resource, action)
}

// GetAPIKeyPolicies gets all policies for a specific API key
func GetAPIKeyPolicies(apiKeyID string) [][]string {
	return GetPoliciesForSubject(apiKeyID)
}

// RemoveAllAPIKeyPolicies removes all policies for a specific API key
func RemoveAllAPIKeyPolicies(apiKeyID string) error {
	e := GetEnforcer()
	if e == nil {
		return fmt.Errorf("enforcer not initialized")
	}

	policies := GetPoliciesForSubject(apiKeyID)
	for _, policy := range policies {
		if len(policy) >= 3 {
			_, err := e.RemovePolicy(policy[0], policy[1], policy[2])
			if err != nil {
				return fmt.Errorf("failed to remove policy: %v", err)
			}
		}
	}
	return nil
}

// CheckAPIKeyPermission checks if an API key has permission to perform an action on a resource
func CheckAPIKeyPermission(apiKeyID, resource, action string) (bool, error) {
	return CheckPermission(apiKeyID, resource, action)
}

// MapPermissionToResource maps API key permissions to resources and actions
func MapPermissionToResource(permission string) ([]string, []string) {
	switch permission {
	case "read":
		return []string{"/api/v1/public/files", "/api/v1/public/packages", "/api/v1/public/versions/*"}, []string{"GET"}
	case "download":
		return []string{"/api/v1/public/files/*", "/api/v1/public/versions/*/latest/download"}, []string{"GET"}
	case "upload":
		return []string{"/api/v1/public/files/upload", "/api/v1/public/upload/*", "/api/v1/public/packages/*/remark"}, []string{"POST", "PATCH"}
	case "delete":
		return []string{"/api/v1/public/files/*"}, []string{"DELETE"}
	case "admin":
		return []string{"/api/v1/public/*"}, []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	default:
		return []string{}, []string{}
	}
}

// CreateAPIKeyPolicies creates all necessary policies for an API key based on its permissions
func CreateAPIKeyPolicies(apiKeyID string, permissions []string) error {
	for _, permission := range permissions {
		if err := createPoliciesForPermission(apiKeyID, permission); err != nil {
			return err
		}
	}
	return nil
}

func createPoliciesForPermission(apiKeyID, permission string) error {
	resources, actions := MapPermissionToResource(permission)

	for _, resource := range resources {
		if err := createPoliciesForResource(apiKeyID, resource, actions, permission); err != nil {
			return err
		}
	}
	return nil
}

func createPoliciesForResource(apiKeyID, resource string, actions []string, permission string) error {
	for _, action := range actions {
		_, err := AddAPIKeyPolicy(apiKeyID, resource, action)
		if err != nil {
			return fmt.Errorf("failed to add policy for %s: %v", permission, err)
		}
	}
	return nil
}
