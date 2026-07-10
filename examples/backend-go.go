// KaizoCore — Backend integration (Go)
//
// Environment variables required:
//   KAIZO_API_KEY=sk_live_xxx    ← your secret key from app.kaizocore.com/api-keys
//
// That's the only env var you need. The HMAC is derived directly from your
// secret key — there is no separate HMAC secret.
//
// Run:  go run backend-go.go

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const kaizoAPIURL = "https://api.kaizocore.com"

// ─────────────────────────────────────────────────────────────────────────────
// KaizoDecision — response from /v1/decide
// ─────────────────────────────────────────────────────────────────────────────

type KaizoDecision struct {
	Decision    string   `json:"decision"`     // ALLOW | ALLOW_WATCH | SOFT_CHALLENGE | REVIEW | BLOCK
	Score       float64  `json:"score"`        // 0–100 (higher = more suspicious)
	Reasons     []string `json:"reasons"`
	SessionMode string   `json:"session_mode"` // e.g. "FORGE:BOUND"
	LatencyMS   int      `json:"latency_ms"`
	RequestID   string   `json:"request_id"`
}

// ─────────────────────────────────────────────────────────────────────────────
// DecideParams — inputs to kaizoDecide
// ─────────────────────────────────────────────────────────────────────────────

type DecideParams struct {
	IP          string            // visitor IP from your web framework
	UserAgent   string            // User-Agent header from the browser request
	KzSt        string            // value of the kz_st cookie (set automatically by c.js)
	EventType   string            // "login" | "checkout" | "signup" | "payment" | etc.
	EntityKeys  map[string]string // optional: { "user_id": "123", "email": "..." }
}

// ─────────────────────────────────────────────────────────────────────────────
// kaizoDecide — signs the request and calls /v1/decide
//
// HMAC-SHA256: the key is []byte(apiKey) — the sk_live_xxx string as UTF-8 bytes.
// Do NOT hex-decode the key. There is no separate HMAC secret.
// ─────────────────────────────────────────────────────────────────────────────

func kaizoDecide(ctx context.Context, params DecideParams) (*KaizoDecision, error) {
	apiKey := os.Getenv("KAIZO_API_KEY")
	if apiKey == "" || !strings.HasPrefix(apiKey, "sk_live_") {
		return nil, errors.New("KaizoCore: KAIZO_API_KEY must be set to sk_live_xxx")
	}

	ts  := strconv.FormatInt(time.Now().Unix(), 10)
	rid := newUUID()

	// Build request body
	type requestBody struct {
		IP           string            `json:"ip"`
		UserAgent    string            `json:"user_agent"`
		SessionToken string            `json:"session_token"`
		EventType    string            `json:"event_type"`
		EntityKeys   map[string]string `json:"entity_keys"`
		Timestamp    int64             `json:"timestamp"`
	}
	ts64, _ := strconv.ParseInt(ts, 10, 64)
	payload, err := json.Marshal(requestBody{
		IP:           params.IP,
		UserAgent:    params.UserAgent,
		SessionToken: params.KzSt,
		EventType:    params.EventType,
		EntityKeys:   params.EntityKeys,
		Timestamp:    ts64,
	})
	if err != nil {
		return nil, fmt.Errorf("KaizoCore: marshal error: %w", err)
	}

	// Compute body hash
	h := sha256.New()
	h.Write(payload)
	bodyHash := hex.EncodeToString(h.Sum(nil))

	// Signing string: POST\n/v1/decide\n{ts}\n{bodyHash}\n{rid}
	sigStr := strings.Join([]string{"POST", "/v1/decide", ts, bodyHash, rid}, "\n")

	// HMAC-SHA256 with sk_live_xxx as the key (UTF-8 bytes, not hex-decoded)
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(sigStr))
	sig := hex.EncodeToString(mac.Sum(nil))

	// Build and send the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kaizoAPIURL+"/v1/decide", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("KaizoCore: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KZ-Key", apiKey)
	req.Header.Set("X-KZ-Ts", ts)
	req.Header.Set("X-KZ-Sig", sig)
	req.Header.Set("X-KZ-Rid", rid)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("KaizoCore: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		return nil, fmt.Errorf("KaizoCore: rate limited, retry after %s seconds", retryAfter)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("KaizoCore: decide failed %d: %s", resp.StatusCode, body)
	}

	var decision KaizoDecision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, fmt.Errorf("KaizoCore: decode response: %w", err)
	}
	return &decision, nil
}

// newUUID generates a random UUID v4.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// ─────────────────────────────────────────────────────────────────────────────
// KaizoHandler — http.Handler wrapper
//
// Wraps any http.Handler and enforces KaizoCore bot detection on all POST
// requests. Read the kz_st cookie — set automatically by c.js on your domain.
//
// Usage:
//   mux.Handle("/api/checkout", KaizoHandler("checkout", checkoutHandler))
// ─────────────────────────────────────────────────────────────────────────────

func KaizoHandler(eventType string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce on mutating requests
		if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
			next.ServeHTTP(w, r)
			return
		}

		// Read the kz_st cookie — sent automatically by the browser (same-origin)
		cookie, err := r.Cookie("kz_st")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"session_missing"}`))
			return
		}

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}

		result, err := kaizoDecide(r.Context(), DecideParams{
			IP:        ip,
			UserAgent: r.Header.Get("User-Agent"),
			KzSt:      cookie.Value,
			EventType: eventType,
		})
		if err != nil {
			// Fail open on unexpected errors — log for alerting
			log.Printf("KaizoCore error: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("[kaizo] %s decision=%s score=%.1f", eventType, result.Decision, result.Score)

		if result.Decision == "BLOCK" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"blocked"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Example handlers
// ─────────────────────────────────────────────────────────────────────────────

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	// KaizoHandler has already verified the session — just process the order
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Order placed!",
		"order_id": fmt.Sprintf("ord_%d", time.Now().UnixMilli()),
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// KaizoHandler has already verified the session — authenticate the user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged in!"})
}

// ─────────────────────────────────────────────────────────────────────────────
// Alternatively: call kaizoDecide directly inside your handler
// ─────────────────────────────────────────────────────────────────────────────

func paymentHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("kz_st")
	if err != nil {
		http.Error(w, `{"error":"session_missing"}`, http.StatusForbidden)
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}

	result, err := kaizoDecide(r.Context(), DecideParams{
		IP:        ip,
		UserAgent: r.Header.Get("User-Agent"),
		KzSt:      cookie.Value,
		EventType: "payment",
		EntityKeys: map[string]string{
			"user_id": r.Header.Get("X-User-ID"), // from your auth middleware
		},
	})
	if err != nil {
		log.Printf("KaizoCore error: %v", err)
		// Fail open
		result = &KaizoDecision{Decision: "ALLOW"}
	}

	switch result.Decision {
	case "BLOCK":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"blocked"}`))
		return
	case "SOFT_CHALLENGE":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"action":"challenge_required"}`))
		return
	case "REVIEW":
		// Log for ops; respond optimistically
		log.Printf("[kaizo] payment queued for review: score=%.1f reasons=%v", result.Score, result.Reasons)
	}

	// Process payment
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Payment processed!"})
}

// ─────────────────────────────────────────────────────────────────────────────
// main — wire up routes
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	mux := http.NewServeMux()

	// Use KaizoHandler wrapper for clean route protection
	mux.Handle("/api/checkout", KaizoHandler("checkout", http.HandlerFunc(checkoutHandler)))
	mux.Handle("/api/login",    KaizoHandler("login",    http.HandlerFunc(loginHandler)))

	// Or call kaizoDecide directly inside the handler
	mux.HandleFunc("/api/payment", paymentHandler)

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
