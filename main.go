package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/gif"
	_ "image/png"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/nfnt/resize"
)

//go:embed index.html
var indexHTML []byte

//go:embed README.md
var readmeContent []byte

// --- Global Configuration and Constants ---
type Config struct {
	Bind      string `json:"bind"`
	TLS       bool   `json:"tls"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	VisitLog  string `json:"visit_log"`
	DataDir   string `json:"data_dir"`
	UsersFile string `json:"users_file"`
}

type contextKey string

const userContextKey = contextKey("username")

type MessageRecord struct {
	FilePath  string `json:"filePath"`
	FileName  string `json:"fileName"`
	IsText    bool   `json:"isText"`
	Content   string `json:"content"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"timestamp"`
}

var (
	config        Config
	users         = make(map[string]string)
	historyMutex  = &sync.Mutex{}
	sm            *SessionManager
)

const (
	defaultConfigPath = "config.json"
	thumbWidth        = 400
	wwwDir            = "www"
	sessionCookieName = "session_id"
	sessionDuration   = 30 * 24 * time.Hour
)

// --- Session Management ---

type SessionData struct {
	Username   string    `json:"username"`
	LastAccess time.Time `json:"lastAccess"`
}

type SessionManager struct {
	sessions   map[string]SessionData
	mutex      sync.RWMutex
	isDirty    bool
	filePath   string
}

func NewSessionManager(filePath string) *SessionManager {
	manager := &SessionManager{
		sessions: make(map[string]SessionData),
		filePath: filePath,
	}
	manager.loadSessions()
	return manager
}

func (sm *SessionManager) loadSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	content, err := os.ReadFile(sm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Session file not found, starting with empty session map.")
			return
		}
		log.Printf("WARN: Failed to read session file: %v. Starting with empty session map.", err)
		return
	}

	if err := json.Unmarshal(content, &sm.sessions); err != nil {
		log.Printf("WARN: Failed to unmarshal session file: %v. Starting with empty session map.", err)
		sm.sessions = make(map[string]SessionData)
	}
	log.Printf("Successfully loaded %d sessions.", len(sm.sessions))
}

func (sm *SessionManager) saveSessions() {
	sm.mutex.RLock()

	if !sm.isDirty {
		sm.mutex.RUnlock()
		return
	}
	log.Println("Saving updated sessions to disk...")
	content, err := json.MarshalIndent(sm.sessions, "", "  ")
	sm.mutex.RUnlock() // Unlock before I/O operation

	if err != nil {
		log.Printf("ERROR: Failed to marshal sessions: %v", err)
		return
	}
	if err := os.WriteFile(sm.filePath, content, 0600); err != nil {
		log.Printf("ERROR: Failed to write session file: %v", err)
	}
	
	sm.mutex.Lock()
	sm.isDirty = false
	sm.mutex.Unlock()
}

func (sm *SessionManager) CreateSession(username string) (string, error) {
	sessionID, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	
	sm.mutex.Lock()
	sm.sessions[sessionID] = SessionData{
		Username:   username,
		LastAccess: truncateToDay(time.Now()),
	}
	sm.isDirty = true
	sm.mutex.Unlock()
	
	sm.saveSessions()
	return sessionID, nil
}

func (sm *SessionManager) ValidateSession(sessionID string) (*SessionData, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	if time.Since(session.LastAccess) > sessionDuration {
		return nil, fmt.Errorf("session expired")
	}
	return &session, nil
}

func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mutex.Lock()
	if _, ok := sm.sessions[sessionID]; ok {
		delete(sm.sessions, sessionID)
		sm.isDirty = true
	}
	sm.mutex.Unlock()

	sm.saveSessions()
}

func (sm *SessionManager) UpdateAndCleanSessions(currentSessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	today := truncateToDay(time.Now())
	
	if data, ok := sm.sessions[currentSessionID]; ok {
		if data.LastAccess.Before(today) {
			data.LastAccess = today
			sm.sessions[currentSessionID] = data
			sm.isDirty = true
			log.Printf("Session for user '%s' updated to new day.", data.Username)
		}
	}

	for id, data := range sm.sessions {
		if time.Since(data.LastAccess) > sessionDuration {
			delete(sm.sessions, id)
			sm.isDirty = true
			log.Printf("Cleaned up expired session for user '%s'", data.Username)
		}
	}
}


// --- History Management Core ---
func modifyHistory(username string, modifier func(records []MessageRecord) []MessageRecord) error {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	historyPath := filepath.Join(config.DataDir, username, "messages.json")
	var records []MessageRecord
	if _, err := os.Stat(historyPath); err == nil {
		content, err := os.ReadFile(historyPath)
		if err != nil {
			return fmt.Errorf("could not read history file: %w", err)
		}
		if len(content) > 0 {
			if err := json.Unmarshal(content, &records); err != nil {
				log.Printf("WARN: Could not unmarshal history for user '%s', starting new history. Error: %v", username, err)
			}
		}
	}

	updatedRecords := modifier(records)
	thirtyDaysAgo := time.Now().Add(-sessionDuration).UnixMilli()
	recentRecords := make([]MessageRecord, 0)
	for _, rec := range updatedRecords {
		if rec.Timestamp >= thirtyDaysAgo {
			recentRecords = append(recentRecords, rec)
		}
	}
	sort.Slice(recentRecords, func(i, j int) bool {
		return recentRecords[i].Timestamp < recentRecords[j].Timestamp
	})
	content, err := json.MarshalIndent(recentRecords, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal updated history: %w", err)
	}
	return os.WriteFile(historyPath, content, 0644)
}

func addRecordToHistory(username string, newRecord MessageRecord) error {
	return modifyHistory(username, func(records []MessageRecord) []MessageRecord {
		return append(records, newRecord)
	})
}

func removeRecordFromHistory(username, relativePathToRemove string) error {
	return modifyHistory(username, func(records []MessageRecord) []MessageRecord {
		var newRecords []MessageRecord
		for _, rec := range records {
			if rec.FilePath != relativePathToRemove {
				newRecords = append(newRecords, rec)
			}
		}
		return newRecords
	})
}

// --- Security Helper Function ---
func resolveAndCheckPath(username, requestPath string) (string, error) {
	userDir := filepath.Join(config.DataDir, username)
	cleanRequestPath := filepath.Clean(filepath.FromSlash(requestPath))
	var fullPath string

	if strings.HasPrefix(filepath.ToSlash(cleanRequestPath), filepath.ToSlash(config.DataDir)) {
		fullPath = cleanRequestPath
	} else {
		fullPath = filepath.Join(userDir, cleanRequestPath)
	}

	if !strings.HasPrefix(filepath.ToSlash(fullPath), filepath.ToSlash(userDir)) {
		log.Printf("SECURITY: Permission denied. User '%s' attempted to access forbidden path '%s'", username, requestPath)
		return "", fmt.Errorf("forbidden: access to this path is not allowed")
	}
	return fullPath, nil
}

// --- HTTP Handlers ---

func sessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"Unauthorized: Please log in."}`, http.StatusUnauthorized)
			return
		}
		sessionID := cookie.Value

		sessionData, err := sm.ValidateSession(sessionID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"Unauthorized: Invalid session. Please log in again."}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, sessionData.Username)
		
		next.ServeHTTP(w, r.WithContext(ctx))

		sm.UpdateAndCleanSessions(sessionID)
		sm.saveSessions() 

		newCookie := http.Cookie{
			Name:     sessionCookieName,
			Value:    sessionID,
			Path:     "/",
			Expires:  time.Now().Add(sessionDuration),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   config.TLS,
		}
		http.SetCookie(w, &newCookie)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	storedPass, userOk := users[creds.Username]
	if !userOk || storedPass != creds.Password {
		log.Printf("Login failed for user=%s from=%s", creds.Username, r.RemoteAddr)
		http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	sessionID, err := sm.CreateSession(creds.Username)
	if err != nil {
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   config.TLS,
	})

	log.Printf("Login successful for user=%s from=%s", creds.Username, r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sm.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   config.TLS,
		MaxAge:   -1,
	})
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}


func uploadHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	isText := r.FormValue("isText") == "true"
	textContent := r.FormValue("textContent")

	r.ParseMultipartForm(1 << 30)
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	now := time.Now()
	weekday := now.Weekday()
	daysToSubtract := (int(weekday) - int(time.Monday) + 7) % 7
	firstDayOfWeek := now.AddDate(0, 0, -daysToSubtract)
	weekDir := firstDayOfWeek.Format("2006-01-02")

	userUploadPath := filepath.Join(config.DataDir, username)
	if err := os.MkdirAll(userUploadPath, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	weeklyUploadPath := filepath.Join(userUploadPath, weekDir)
	if err := os.MkdirAll(weeklyUploadPath, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	safeFilename := filepath.Base(handler.Filename)
	destPath := filepath.Join(weeklyUploadPath, safeFilename)
	log.Printf("User '%s' received file: %s, saving to: %s", username, handler.Filename, destPath)

	destFile, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	size, err := io.Copy(destFile, file)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	relativePath := filepath.Join(weekDir, safeFilename)

	newRecord := MessageRecord{
		FilePath:  filepath.ToSlash(relativePath),
		FileName:  safeFilename,
		IsText:    isText,
		Content:   textContent,
		Size:      size,
		Timestamp: time.Now().UnixMilli(),
	}

	if err := addRecordToHistory(username, newRecord); err != nil {
		log.Printf("ERROR: Failed to update history for user '%s': %v", username, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"filePath": newRecord.FilePath})
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	var payload struct {
		FilePath string `json:"filePath"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	safeFullPath, err := resolveAndCheckPath(username, payload.FilePath)
	if err != nil {
		http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
		return
	}

	err = os.Remove(safeFullPath)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error deleting file %s: %v", safeFullPath, err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("User '%s' successfully deleted file: %s", username, safeFullPath)

	thumbFilename := filepath.Base(safeFullPath) + ".jpg"
	thumbPath := filepath.Join(filepath.Dir(safeFullPath), "thumb", thumbFilename)
	err = os.Remove(thumbPath)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("WARN: Could not delete thumbnail %s: %v", thumbPath, err)
	} else if err == nil {
		log.Printf("Successfully deleted thumbnail: %s", thumbPath)
	}

	var relativePathToRemove string
	cleanRequestPath := filepath.Clean(filepath.FromSlash(payload.FilePath))
	if strings.HasPrefix(cleanRequestPath, config.DataDir) {
		userDir := filepath.Join(config.DataDir, username)
		relativePathToRemove = strings.TrimPrefix(safeFullPath, userDir+string(os.PathSeparator))
	} else {
		relativePathToRemove = cleanRequestPath
	}

	if err := removeRecordFromHistory(username, filepath.ToSlash(relativePathToRemove)); err != nil {
		log.Printf("WARN: File at %s deleted, but failed to update history for user '%s': %v", payload.FilePath, username, err)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "File deleted successfully"})
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	historyPath := filepath.Join(config.DataDir, username, "messages.json")
	if _, err := os.Stat(historyPath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
		return
	}
	http.ServeFile(w, r, historyPath)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Bad Request: 'path' parameter is missing", http.StatusBadRequest)
		return
	}

	safeFullPath, err := resolveAndCheckPath(username, filePath)
	if err != nil {
		http.Error(w, `{"error":"Forbidden"}`, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(safeFullPath)+"\"")
	http.ServeFile(w, r, safeFullPath)
}

func previewHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	filePath := strings.TrimPrefix(r.URL.Path, "/preview/")
	if filePath == "" {
		http.Error(w, "Bad Request: file path is missing", http.StatusBadRequest)
		return
	}

	originalPath, err := resolveAndCheckPath(username, filePath)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	thumbDir := filepath.Join(filepath.Dir(originalPath), "thumb")
	thumbFilename := filepath.Base(originalPath) + ".jpg"
	thumbPath := filepath.Join(thumbDir, thumbFilename)

	originalInfo, err := os.Stat(originalPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	thumbInfo, err := os.Stat(thumbPath)

	if os.IsNotExist(err) || thumbInfo.ModTime().Before(originalInfo.ModTime()) {
		log.Printf("Generating thumbnail for %s", originalPath)

		file, err := os.Open(originalPath)
		if err != nil {
			log.Printf("ERROR: Could not open original file for thumbnailing: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		img, _, err := image.Decode(file)
		if err != nil {
			log.Printf("ERROR: Could not decode image for thumbnailing: %v", err)
			http.Error(w, "Bad Request: Not a valid image", http.StatusBadRequest)
			return
		}

		m := resize.Resize(uint(thumbWidth), 0, img, resize.Lanczos3)

		if err := os.MkdirAll(thumbDir, 0755); err != nil {
			log.Printf("ERROR: Could not create thumb directory: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		out, err := os.Create(thumbPath)
		if err != nil {
			log.Printf("ERROR: Could not create thumb file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		options := &jpeg.Options{Quality: 85}
		if err := jpeg.Encode(out, m, options); err != nil {
			log.Printf("ERROR: Could not encode thumb file as JPEG: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	http.ServeFile(w, r, thumbPath)
}

// --- Setup and Helper Functions ---
func truncateToDay(t time.Time) time.Time {
	return t.Truncate(24 * time.Hour)
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func releaseStaticFiles() {
	indexPath := filepath.Join(wwwDir, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		log.Printf("Static file '%s' not found, creating from embedded content...", indexPath)
		if err := os.MkdirAll(wwwDir, 0755); err != nil {
			log.Fatalf("FATAL: Failed to create www directory: %v", err)
		}
		if err := os.WriteFile(indexPath, indexHTML, 0644); err != nil {
			log.Fatalf("FATAL: Failed to write index.html: %v", err)
		}
		log.Printf("Successfully created '%s'", indexPath)
	} else {
		log.Printf("Static file '%s' already exists, skipping creation.", indexPath)
	}
}

func generateReadmeIfNeeded() {
	readmePath := "README.md"
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		log.Printf("README.md not found, generating one...")
		err := os.WriteFile(readmePath, readmeContent, 0644)
		if err != nil {
			log.Printf("WARN: Failed to write README.md: %v", err)
		} else {
			log.Printf("Successfully generated %s", readmePath)
		}
	}
}

func loadConfig() {
	defaultConfig := Config{
		Bind:      ":8094", TLS: true, CertFile: "cert.pem", KeyFile: "key.pem",
		VisitLog: "visit.log", DataDir: "data", UsersFile: "users.txt",
	}
	if _, err := os.Stat(defaultConfigPath); os.IsNotExist(err) {
		log.Printf("Config file '%s' not found, creating default...", defaultConfigPath)
		file, _ := json.MarshalIndent(defaultConfig, "", "  ")
		os.WriteFile(defaultConfigPath, file, 0644)
		config = defaultConfig
	} else {
		file, _ := os.ReadFile(defaultConfigPath)
		json.Unmarshal(file, &config)
		log.Printf("Successfully loaded config from '%s'", defaultConfigPath)
	}
	os.MkdirAll(config.DataDir, 0755)
}

func generateRandomPassword(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, v := range b {
		b[i] = chars[v%byte(len(chars))]
	}
	return string(b), nil
}

func loadUsers() {
	if _, err := os.Stat(config.UsersFile); os.IsNotExist(err) {
		log.Printf("User file '%s' not found, creating default user 'admin'...", config.UsersFile)
		password, _ := generateRandomPassword(12)
		content := fmt.Sprintf("admin:%s\n", password)
		os.WriteFile(config.UsersFile, []byte(content), 0600)
		log.Println("=======================================================")
		log.Printf("Default user created:\n  Username: admin\n  Password: %s", password)
		log.Println("\nPlease store this password securely!")
		log.Println("=======================================================")
	}
	content, _ := os.ReadFile(config.UsersFile)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			users[parts[0]] = parts[1]
		}
	}
	log.Printf("Successfully loaded %d user(s).", len(users))
}

func checkAndGenerateCerts() {
	if _, err := os.Stat(config.CertFile); !os.IsNotExist(err) {
		if _, err := os.Stat(config.KeyFile); !os.IsNotExist(err) {
			return
		}
	}
	log.Printf("Certificate not found, generating new self-signed certificate...")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber, Subject: pkix.Name{Organization: []string{"Mobile Upload Self-Signed"}},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	template.DNSNames = append(template.DNSNames, "localhost")
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				template.IPAddresses = append(template.IPAddresses, ipnet.IP)
			}
		}
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certOut, _ := os.Create(config.CertFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := os.OpenFile(config.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Printf("Generated certificate and key files: %s, %s", config.CertFile, config.KeyFile)
}

func main() {
	loadConfig()
	loadUsers()
	generateReadmeIfNeeded()
	releaseStaticFiles()
	
	sm = NewSessionManager("sessions.json")

	if config.VisitLog != "" {
		logFile, err := os.OpenFile(config.VisitLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", config.VisitLog, err)
		}
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	// API routes that need authentication
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/upload", uploadHandler)
	apiMux.HandleFunc("/delete", deleteHandler)
	apiMux.HandleFunc("/history", historyHandler)
	apiMux.HandleFunc("/download", downloadHandler)
	apiMux.HandleFunc("/preview/", previewHandler)
	apiMux.HandleFunc("/logout", logoutHandler)
	
	// Create a handler for all API endpoints, wrapped in the sessionAuth middleware
	apiHandler := sessionAuth(apiMux)

	// Main router
	mainMux := http.NewServeMux()
	mainMux.Handle("/", http.FileServer(http.Dir(wwwDir)))
	mainMux.HandleFunc("/login", loginHandler)
	// All API paths are routed to the single, wrapped apiHandler
	mainMux.Handle("/upload", apiHandler)
	mainMux.Handle("/delete", apiHandler)
	mainMux.Handle("/history", apiHandler)
	mainMux.Handle("/download", apiHandler)
	mainMux.Handle("/preview/", apiHandler)
	mainMux.Handle("/logout", apiHandler)

	log.Printf("Server starting, listening on %s", config.Bind)
	if config.TLS {
		log.Println("TLS is enabled.")
		checkAndGenerateCerts()
		err := http.ListenAndServeTLS(config.Bind, config.CertFile, config.KeyFile, mainMux)
		if err != nil {
			log.Fatalf("Server startup failed: %v", err)
		}
	} else {
		log.Println("TLS is disabled, using plain HTTP.")
		err := http.ListenAndServe(config.Bind, mainMux)
		if err != nil {
			log.Fatalf("Server startup failed: %v", err)
		}
	}
}