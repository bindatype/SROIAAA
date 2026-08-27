package connector

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/maclach/sroiaaa/internal/broker"
)

const (
	pegasusDefaultTimeout = 30 * time.Second
	pegasusDefaultMaxRows = 1000
	pegasusMaxCellBytes   = 4096
	pegasusMaxTotalBytes  = 512 * 1024
)

// PegasusConfig carries operator-supplied connection details.
//
// Unlike the other connectors this one executes a query the model authored, so
// the controls here are about resource use and result size rather than about
// which operations exist. The credential grants SELECT on one schema and
// cannot write, which is what makes that acceptable.
type PegasusConfig struct {
	DSN              string
	Timeout          time.Duration
	MaxRows          int
	MaxBytes         int
	StatementTimeout time.Duration
}

// PegasusConnector runs read-only queries against the accounting database.
type PegasusConnector struct {
	db               *sql.DB
	maxRows          int
	maxBytes         int
	statementTimeout time.Duration
	endpoint         string
}

// NewPegasusConnector validates configuration and opens a pooled connection.
func NewPegasusConnector(config PegasusConfig) (*PegasusConnector, error) {
	if config.DSN == "" {
		return nil, fmt.Errorf("pegasus DSN is required")
	}
	parsed, err := mysql.ParseDSN(config.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse pegasus DSN: %w", err)
	}
	if parsed.DBName == "" {
		return nil, fmt.Errorf("pegasus DSN must name a database")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = pegasusDefaultTimeout
	}
	maxRows := config.MaxRows
	if maxRows <= 0 {
		maxRows = pegasusDefaultMaxRows
	}
	maxBytes := config.MaxBytes
	if maxBytes <= 0 {
		maxBytes = pegasusMaxTotalBytes
	}
	statementTimeout := config.StatementTimeout
	if statementTimeout <= 0 {
		statementTimeout = timeout
	}

	db, err := sql.Open("mysql", config.DSN)
	if err != nil {
		return nil, fmt.Errorf("open pegasus: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &PegasusConnector{
		db:               db,
		maxRows:          maxRows,
		maxBytes:         maxBytes,
		statementTimeout: statementTimeout,
		// Recorded for provenance without the credential the DSN carries.
		endpoint: parsed.Addr + "/" + parsed.DBName,
	}, nil
}

// Close releases pooled connections.
func (c *PegasusConnector) Close() error { return c.db.Close() }

// Source reports which route-step source this connector serves.
func (c *PegasusConnector) Source() broker.Source {
	return broker.SourcePegasusDB
}

// Execute runs one query and returns normalized evidence.
func (c *PegasusConnector) Execute(ctx context.Context, step broker.RouteStep) (Evidence, error) {
	if step.Source != broker.SourcePegasusDB {
		return Evidence{}, newConnectorError("wrong_source", "step is not a pegasus-db step")
	}
	if step.Action != "query.execute" {
		return Evidence{}, newConnectorError("unsupported_action", fmt.Sprintf("action %q is not executable", step.Action))
	}
	// The planner validated the query's shape. Re-checking here keeps the
	// connector safe to call directly, and costs nothing.
	if err := broker.ValidateQuery(step.Query); err != nil {
		return Evidence{}, newConnectorError("invalid_query", err.Error())
	}

	rowLimit := c.maxRows
	if step.Limit > 0 && step.Limit < rowLimit {
		rowLimit = step.Limit
	}

	requestedAt := time.Now().UTC()
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return Evidence{}, newConnectorError("transport", err.Error())
	}
	defer conn.Close()

	// The server's default statement time limit is unlimited, so a query
	// joining several million rows would run until it finished or the server
	// suffered. Read-only means non-destructive to data, not to service.
	millis := c.statementTimeout.Milliseconds()
	if _, err := conn.ExecContext(ctx, "SET SESSION max_statement_time = ?", float64(millis)/1000.0); err != nil {
		return Evidence{}, newConnectorError("transport", "could not bound statement time: "+err.Error())
	}

	rows, err := conn.QueryContext(ctx, step.Query)
	if err != nil {
		return Evidence{}, newConnectorError("query_failed", err.Error())
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return Evidence{}, newConnectorError("query_failed", err.Error())
	}

	items, truncated, err := scanRows(rows, columns, rowLimit, c.maxBytes)
	if err != nil {
		return Evidence{}, err
	}

	summary := map[string]int{
		"returned": len(items),
		"columns":  len(columns),
	}
	if truncated {
		summary["row_limit"] = rowLimit
	}

	return Evidence{
		Source:      string(broker.SourcePegasusDB),
		Action:      step.Action,
		Endpoint:    c.endpoint,
		Query:       step.Query,
		RequestedAt: requestedAt,
		DurationMS:  time.Since(requestedAt).Milliseconds(),
		ItemCount:   len(items),
		Truncated:   truncated,
		Summary:     summary,
		Items:       items,
	}, nil
}

// scanRows converts result rows into evidence items, stopping at the row limit
// or the total byte budget, whichever comes first. A query returning eighteen
// million rows is a legitimate SELECT that no context window can hold, so the
// bound is enforced here rather than trusted to the query.
func scanRows(rows *sql.Rows, columns []string, maxRows, maxBytes int) ([]EvidenceItem, bool, error) {
	items := make([]EvidenceItem, 0, 64)
	totalBytes := 0

	for rows.Next() {
		if len(items) >= maxRows {
			return items, true, nil
		}

		holders := make([]any, len(columns))
		for i := range holders {
			holders[i] = new(sql.RawBytes)
		}
		if err := rows.Scan(holders...); err != nil {
			return nil, false, newConnectorError("scan_failed", err.Error())
		}

		fields := make(map[string]string, len(columns))
		for i, column := range columns {
			raw := *(holders[i].(*sql.RawBytes))
			value := string(raw)
			if raw == nil {
				value = ""
			}
			if len(value) > pegasusMaxCellBytes {
				value = value[:pegasusMaxCellBytes] + "…"
			}
			fields[column] = value
			totalBytes += len(column) + len(value)
		}

		items = append(items, EvidenceItem{
			ID:     strconv.Itoa(len(items)),
			Fields: fields,
		})

		if totalBytes >= maxBytes {
			return items, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		// A statement killed by max_statement_time surfaces here rather than at
		// query time, and reads as an ordinary read error unless named.
		if strings.Contains(err.Error(), "max_statement_time") {
			return nil, false, newConnectorError("query_timeout", "query exceeded the configured statement time limit")
		}
		return nil, false, newConnectorError("query_failed", err.Error())
	}
	return items, false, nil
}
