// +build cgo

package modsecurity

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lmodsecurity -Wl,-rpath,/usr/local/lib
#include <stdlib.h>
#include <string.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

// Helper function to create a transaction
Transaction* create_transaction(ModSecurity *ms, RulesSet *rules, const char *id) {
    return msc_new_transaction(ms, rules, (void*)id);
}

// Helper function to check for intervention
int check_intervention(Transaction *transaction, ModSecurityIntervention *intervention) {
    if (!transaction || !intervention) return 0;
    memset(intervention, 0, sizeof(ModSecurityIntervention));
    return msc_intervention(transaction, intervention);
}
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ModSecurity{})
	httpcaddyfile.RegisterHandlerDirective("modsecurity", parseCaddyfile)
	// Register early in the chain, right after rewrite but before any handlers
	// This ensures WAF inspects all requests regardless of the handler
	httpcaddyfile.RegisterDirectiveOrder("modsecurity", "before", "encode")
}

// ============================================================================
// CGo Wrapper Types and Functions
// ============================================================================

// WAF represents a ModSecurity WAF instance
type WAF struct {
    modsec *C.ModSecurity
    rules  *C.RulesSet
    logger *zap.Logger // add this
}
// Transaction represents a single HTTP request/response transaction
type Transaction struct {
	transaction *C.Transaction
	waf         *WAF
}

// Intervention represents ModSecurity's decision on a transaction
type Intervention struct {
	Status     int
	URL        string
	Log        string
	Disruptive bool
}

// NewWAF creates a new ModSecurity WAF instance
func NewWAF() (*WAF, error) {
	modsec := C.msc_init()
	if modsec == nil {
		return nil, errors.New("failed to initialize ModSecurity")
	}

	rules := C.msc_create_rules_set()
	if rules == nil {
		C.msc_cleanup(modsec)
		return nil, errors.New("failed to create rules set")
	}

	return &WAF{
		modsec: modsec,
		rules:  rules,
	}, nil
}

// LoadConfig loads the main ModSecurity configuration file
func (w *WAF) LoadConfig(configPath string) error {
	cConfigPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cConfigPath))

	var errMsg *C.char
	result := C.msc_rules_add_file(w.rules, cConfigPath, &errMsg)
	if result < 0 {
		if errMsg != nil {
			defer C.free(unsafe.Pointer(errMsg))
			return fmt.Errorf("failed to load config: %s", C.GoString(errMsg))
		}
		return fmt.Errorf("failed to load config: unknown error")
	}

	return nil
}

// LoadRules loads ModSecurity rules from a file or directory
func (w *WAF) LoadRules(rulesPath string) error {
	cRulesPath := C.CString(rulesPath)
	defer C.free(unsafe.Pointer(cRulesPath))

	var errMsg *C.char
	result := C.msc_rules_add_file(w.rules, cRulesPath, &errMsg)
	if result < 0 {
		if errMsg != nil {
			defer C.free(unsafe.Pointer(errMsg))
			return fmt.Errorf("failed to load rules: %s", C.GoString(errMsg))
		}
		return fmt.Errorf("failed to load rules: unknown error")
	}

	return nil
}

// NewTransaction creates a new transaction for inspecting a request
func (w *WAF) NewTransaction(uniqueID string) *Transaction {
	cUniqueID := C.CString(uniqueID)
	defer C.free(unsafe.Pointer(cUniqueID))

	transaction := C.create_transaction(w.modsec, w.rules, cUniqueID)

	return &Transaction{
		transaction: transaction,
		waf:         w,
	}
}

// ProcessConnection processes the connection phase
func (t *Transaction) ProcessConnection(clientIP string, clientPort int, serverIP string, serverPort int) {
	cClientIP := C.CString(clientIP)
	cServerIP := C.CString(serverIP)
	defer C.free(unsafe.Pointer(cClientIP))
	defer C.free(unsafe.Pointer(cServerIP))

	C.msc_process_connection(
		t.transaction,
		cClientIP,
		C.int(clientPort),
		cServerIP,
		C.int(serverPort),
	)
}

// ProcessURI processes the request URI
func (t *Transaction) ProcessURI(uri string, method string, httpVersion string) {
	cURI := C.CString(uri)
	cMethod := C.CString(method)
	cHTTPVersion := C.CString(httpVersion)
	defer C.free(unsafe.Pointer(cURI))
	defer C.free(unsafe.Pointer(cMethod))
	defer C.free(unsafe.Pointer(cHTTPVersion))

	C.msc_process_uri(t.transaction, cURI, cMethod, cHTTPVersion)
}

// ProcessRequestHeaders processes request headers
func (t *Transaction) ProcessRequestHeaders(headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			cKey := C.CString(key)
			cValue := C.CString(value)
			// Cast to unsigned char pointers
			C.msc_add_request_header(t.transaction, (*C.uchar)(unsafe.Pointer(cKey)), (*C.uchar)(unsafe.Pointer(cValue)))
			C.free(unsafe.Pointer(cKey))
			C.free(unsafe.Pointer(cValue))
		}
	}
	C.msc_process_request_headers(t.transaction)
}

// ProcessRequestBody processes the request body
func (t *Transaction) ProcessRequestBody(body io.Reader) error {
	if body == nil {
		C.msc_process_request_body(t.transaction)
		return nil
	}

	// Read body in chunks
	buf := make([]byte, 8192)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			cBody := C.CBytes(buf[:n])
			C.msc_append_request_body(t.transaction, (*C.uchar)(cBody), C.size_t(n))
			C.free(cBody)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	C.msc_process_request_body(t.transaction)
	return nil
}
func (t *Transaction) transactionID() string {
    return fmt.Sprintf("%p", t.transaction) // or generate a UUID per transaction
}

// GetIntervention checks if ModSecurity requires intervention
func (t *Transaction) GetIntervention() (*Intervention, error) {
    var intervention C.ModSecurityIntervention

    result := C.check_intervention(t.transaction, &intervention)

    if result == 0 {
        // No intervention needed
        return nil, nil
    }

    i := &Intervention{
        Status:     int(intervention.status),
        Disruptive: intervention.disruptive != 0,
    }

    if intervention.url != nil {
        i.URL = C.GoString(intervention.url)
    }
    if intervention.log != nil {
        i.Log = C.GoString(intervention.log)
    }

    // Log the rule triggering info for debugging
 if i.Log != "" && t.waf != nil && t.waf.logger != nil {
    t.waf.logger.Warn("ModSecurity rule triggered",
        zap.String("uri", t.transactionID()),
        zap.String("log", i.Log),
        zap.Int("status", i.Status),
        zap.Bool("disruptive", i.Disruptive),
    )
}   

    return i, nil
}
// Cleanup frees the transaction resources
func (t *Transaction) Cleanup() {
	if t.transaction != nil {
		C.msc_transaction_cleanup(t.transaction)
		t.transaction = nil
	}
}

// Cleanup frees the WAF resources
func (w *WAF) Cleanup() {
	if w.rules != nil {
		C.msc_rules_cleanup(w.rules)
		w.rules = nil
	}
	if w.modsec != nil {
		C.msc_cleanup(w.modsec)
		w.modsec = nil
	}
}

// GetVersion returns the ModSecurity version
func GetVersion(w *WAF) string {
    if w == nil || w.modsec == nil {
        return "ModSecurity not initialized"
    }
    return C.GoString(C.msc_who_am_i(w.modsec))
}
// ============================================================================
// Caddy Plugin
// ============================================================================

// ModSecurity implements an HTTP handler that integrates ModSecurity WAF
type ModSecurity struct {
	// Configuration fields
	Enabled    bool   `json:"enabled,omitempty"`
	RulesPath  string `json:"rules_path,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	AuditLog   string `json:"audit_log,omitempty"`
	BlockMode  bool   `json:"block_mode,omitempty"` // false = detection only

	// Internal state (not serialized)
	waf    *WAF // ModSecurity WAF instance
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information
func (ModSecurity) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.modsecurity",
		New: func() caddy.Module { return new(ModSecurity) },
	}
}

// Provision sets up the ModSecurity module
func (m *ModSecurity) Provision(ctx caddy.Context) error {
	if !m.Enabled {
		return nil
	}

	m.logger = ctx.Logger()

	// Initialize ModSecurity
	waf, err := NewWAF()
	if err != nil {
		return fmt.Errorf("failed to initialize ModSecurity: %w", err)
	}
	waf.logger = m.logger
	m.waf = waf

	// Load configuration
	if err := m.waf.LoadConfig(m.ConfigPath); err != nil {
		m.waf.Cleanup()
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Load rules
	if err := m.waf.LoadRules(m.RulesPath); err != nil {
		m.waf.Cleanup()
		return fmt.Errorf("failed to load rules: %w", err)
	}

	m.logger.Info("modsecurity initialized",
		zap.String("version", GetVersion(m.waf)),
		zap.String("rules_path", m.RulesPath),
		zap.String("config_path", m.ConfigPath),
		zap.Bool("block_mode", m.BlockMode),
	)

	return nil
}

// Validate ensures the module configuration is valid
func (m *ModSecurity) Validate() error {
	if m.Enabled {
		if m.RulesPath == "" {
			return fmt.Errorf("rules_path is required when modsecurity is enabled")
		}
		if m.ConfigPath == "" {
			return fmt.Errorf("config_path is required when modsecurity is enabled")
		}
	}
	return nil
}

// ServeHTTP implements the HTTP handler
func (m ModSecurity) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !m.Enabled || m.waf == nil {
		return next.ServeHTTP(w, r)
	}

	// Create unique transaction ID
	uniqueID := fmt.Sprintf("%s-%d", r.RemoteAddr, time.Now().UnixNano())
	transaction := m.waf.NewTransaction(uniqueID)
	defer transaction.Cleanup()

	// Process connection phase
	clientIP, clientPort := splitHostPort(r.RemoteAddr)
	serverIP, serverPort := splitHostPort(r.Host)
	transaction.ProcessConnection(clientIP, clientPort, serverIP, serverPort)

	// Check for intervention after connection
	if intervention, _ := transaction.GetIntervention(); intervention != nil {
		if m.BlockMode && intervention.Disruptive {
			m.logger.Warn("request blocked at connection phase",
				zap.String("client_ip", clientIP),
				zap.Int("status", intervention.Status),
				zap.String("log", intervention.Log),
			)
			http.Error(w, "Forbidden", intervention.Status)
			return nil
		}
	}

	// Process URI
	uri := r.URL.String()
	transaction.ProcessURI(uri, r.Method, r.Proto)

	// Check for intervention after URI
if intervention, _ := transaction.GetIntervention(); intervention != nil {
    if intervention.Disruptive {
        m.logger.Warn("ModSecurity rule triggered",
            zap.String("uri", r.URL.String()),
            zap.String("log", intervention.Log),
            zap.Int("status", intervention.Status),
            zap.Bool("disruptive", intervention.Disruptive),
        )
        if m.BlockMode {
            http.Error(w, "Forbidden", intervention.Status)
            return nil
        }
    }
}
	// Process request headers
	transaction.ProcessRequestHeaders(r.Header)

	// Check for intervention after headers
	if intervention, _ := transaction.GetIntervention(); intervention != nil {
		if m.BlockMode && intervention.Disruptive {
			m.logger.Warn("request blocked at headers phase",
				zap.String("uri", uri),
				zap.Int("status", intervention.Status),
			)
			http.Error(w, "Forbidden", intervention.Status)
			return nil
		}
	}

	// Process request body if present
	if r.Body != nil {
		// Buffer the body so we can pass it to both ModSecurity and the next handler
		bodyBytes, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}

		// Restore body for next handler
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Process with ModSecurity
		if err := transaction.ProcessRequestBody(bytes.NewBuffer(bodyBytes)); err != nil {
			return fmt.Errorf("failed to process request body: %w", err)
		}

		// Check for intervention after body
		if intervention, _ := transaction.GetIntervention(); intervention != nil {
			if m.BlockMode && intervention.Disruptive {
				m.logger.Warn("request blocked at body phase",
					zap.String("uri", uri),
					zap.Int("status", intervention.Status),
				)
				http.Error(w, "Forbidden", intervention.Status)
				return nil
			}
		}
	}

	// Request passed all checks, continue to next handler
	return next.ServeHTTP(w, r)
}

// splitHostPort splits a host:port string into components
func splitHostPort(hostPort string) (string, int) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// UnmarshalCaddyfile sets up the handler from Caddyfile configuration
func (m *ModSecurity) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "enabled":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var enabled bool
				if d.Val() == "true" {
					enabled = true
				}
				m.Enabled = enabled

			case "rules_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RulesPath = d.Val()

			case "config_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ConfigPath = d.Val()

			case "audit_log":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.AuditLog = d.Val()

			case "block_mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var blockMode bool
				if d.Val() == "true" {
					blockMode = true
				}
				m.BlockMode = blockMode

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m ModSecurity
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ModSecurity)(nil)
	_ caddy.Validator             = (*ModSecurity)(nil)
	_ caddyhttp.MiddlewareHandler = (*ModSecurity)(nil)
	_ caddyfile.Unmarshaler       = (*ModSecurity)(nil)
)
