package authz

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// DatabaseAdapter Casbin数据库适配器
type DatabaseAdapter struct {
	db *sql.DB
}

// NewDatabaseAdapter 创建数据库适配器
func NewDatabaseAdapter(db *sql.DB) *DatabaseAdapter {
	return &DatabaseAdapter{db: db}
}

// LoadPolicy 从数据库加载策略
func (a *DatabaseAdapter) LoadPolicy(model model.Model) error {
	rows, err := a.db.Query("SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_policies")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ptype, v0, v1, v2, v3, v4, v5 sql.NullString
		if err := rows.Scan(&ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
			return err
		}

		// 构建策略行，处理NULL值
		values := []string{}
		if ptype.Valid {
			values = append(values, ptype.String)
		}
		if v0.Valid {
			values = append(values, v0.String)
		}
		if v1.Valid {
			values = append(values, v1.String)
		}
		if v2.Valid {
			values = append(values, v2.String)
		}
		if v3.Valid {
			values = append(values, v3.String)
		}
		if v4.Valid {
			values = append(values, v4.String)
		}
		if v5.Valid {
			values = append(values, v5.String)
		}

		line := strings.Join(values, ", ")
		persist.LoadPolicyLine(line, model)
	}

	return rows.Err()
}

// SavePolicy 保存策略到数据库
func (a *DatabaseAdapter) SavePolicy(model model.Model) error {
	// 清空现有策略
	if _, err := a.db.Exec("DELETE FROM casbin_policies"); err != nil {
		return err
	}

	// 插入新策略
	stmt, err := a.db.Prepare("INSERT INTO casbin_policies (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	// 保存所有策略
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			params := make([]interface{}, 7)
			params[0] = ptype
			for i, v := range rule {
				if i < 6 {
					params[i+1] = v
				}
			}
			if _, err := stmt.Exec(params...); err != nil {
				return err
			}
		}
	}

	// 保存角色继承关系
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			params := make([]interface{}, 7)
			params[0] = ptype
			for i, v := range rule {
				if i < 6 {
					params[i+1] = v
				}
			}
			if _, err := stmt.Exec(params...); err != nil {
				return err
			}
		}
	}

	return nil
}

// AddPolicy 添加策略
func (a *DatabaseAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	params := make([]interface{}, 7)
	params[0] = ptype
	for i, v := range rule {
		if i < 6 {
			params[i+1] = v
		}
	}

	_, err := a.db.Exec("INSERT INTO casbin_policies (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, ?, ?, ?)", params...)
	return err
}

// RemovePolicy 移除策略
func (a *DatabaseAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	query := "DELETE FROM casbin_policies WHERE ptype = ?"
	params := []interface{}{ptype}

	for i, v := range rule {
		if i < 6 {
			query += fmt.Sprintf(" AND v%d = ?", i)
			params = append(params, v)
		}
	}

	_, err := a.db.Exec(query, params...)
	return err
}

// RemoveFilteredPolicy 移除过滤策略
func (a *DatabaseAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := "DELETE FROM casbin_policies WHERE ptype = ?"
	params := []interface{}{ptype}

	for i, v := range fieldValues {
		if v != "" {
			query += fmt.Sprintf(" AND v%d = ?", fieldIndex+i)
			params = append(params, v)
		}
	}

	_, err := a.db.Exec(query, params...)
	return err
}

// 确保接口实现
var _ persist.Adapter = (*DatabaseAdapter)(nil)

// CreateCasbinTable 创建Casbin策略表
func CreateCasbinTable(db *sql.DB) error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS casbin_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ptype TEXT NOT NULL,
		v0 TEXT,
		v1 TEXT,
		v2 TEXT,
		v3 TEXT,
		v4 TEXT,
		v5 TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_casbin_ptype ON casbin_policies(ptype);
	CREATE INDEX IF NOT EXISTS idx_casbin_v0 ON casbin_policies(v0);
	CREATE INDEX IF NOT EXISTS idx_casbin_v1 ON casbin_policies(v1);
	`

	_, err := db.Exec(createTableSQL)
	return err
}

// GetEnforcerWithDB 使用数据库适配器创建Casbin执行器
func GetEnforcerWithDB(db *sql.DB) (*casbin.Enforcer, error) {
	// 创建策略表
	if err := CreateCasbinTable(db); err != nil {
		return nil, fmt.Errorf("failed to create casbin table: %v", err)
	}

    // 加载模型（兼容不同工作目录）
    var (
        m   model.Model
        err error
    )
    candidates := []string{
        "configs/casbin_model.conf",
        "../configs/casbin_model.conf",
        "../../configs/casbin_model.conf",
        "../../../configs/casbin_model.conf",
    }
    for _, p := range candidates {
        m, err = model.NewModelFromFile(p)
        if err == nil {
            break
        }
    }
    if err != nil {
        return nil, fmt.Errorf("failed to load model: %v", err)
    }

	// 创建数据库适配器
	adapter := NewDatabaseAdapter(db)

	// 创建执行器
	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %v", err)
	}

	// 加载策略
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load policy: %v", err)
	}

	return enforcer, nil
}
