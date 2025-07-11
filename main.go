package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
)

//go:embed index.html
var indexHTML []byte

//go:embed README.md
var readmeContent []byte // Embed the README.md file content

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

var config Config
var users = make(map[string]string)
var historyMutex = &sync.Mutex{}
const defaultConfigPath = "config.json"

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
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	recentRecords := make([]MessageRecord, 0)
	for _, rec := range updatedRecords {
		if rec.Timestamp >= sevenDaysAgo {
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

func removeRecordFromHistory(username, filePathToRemove string) error {
	return modifyHistory(username, func(records []MessageRecord) []MessageRecord {
		var newRecords []MessageRecord
		for _, rec := range records {
			if rec.FilePath != filePathToRemove {
				newRecords = append(newRecords, rec)
			}
		}
		return newRecords
	})
}

// --- HTTP Handlers ---
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if storedPass, userOk := users[user]; userOk && storedPass == pass {
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			log.Printf("Authentication failed: incorrect username or password for user=%s, from=%s", user, r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	isText := r.FormValue("isText") == "true"
	textContent := r.FormValue("textContent")

	r.ParseMultipartForm(1 << 30) // Limit upload size to 1GB
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	dateDir := time.Now().Format("2006-01-02")
	userUploadPath := filepath.Join(config.DataDir, username)
	if err := os.MkdirAll(userUploadPath, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	uploadPath := filepath.Join(userUploadPath, dateDir)
	if err := os.MkdirAll(uploadPath, 0755); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	safeFilename := filepath.Base(handler.Filename)
	destPath := filepath.Join(uploadPath, safeFilename)
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

	newRecord := MessageRecord{
		FilePath:  filepath.ToSlash(destPath),
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
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	var payload struct {
		FilePath string `json:"filePath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	cleanPath := filepath.FromSlash(filepath.Clean(payload.FilePath))
	parts := strings.Split(cleanPath, string(os.PathSeparator))
	if len(parts) < 3 || parts[0] != config.DataDir || parts[1] != username {
		log.Printf("Permission denied: User '%s' attempted to delete path '%s'", username, payload.FilePath)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	err := os.Remove(cleanPath)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error deleting file %s: %v", cleanPath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("User '%s' successfully deleted file: %s", username, cleanPath)

	if err := removeRecordFromHistory(username, payload.FilePath); err != nil {
		log.Printf("WARN: File at %s deleted, but failed to update history for user '%s': %v", payload.FilePath, username, err)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "File deleted successfully"})
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Bad Request: 'path' parameter is missing", http.StatusBadRequest)
		return
	}
	cleanPath := filepath.FromSlash(filepath.Clean(filePath))
	expectedPrefix := filepath.Join(config.DataDir, username)
	if !strings.HasPrefix(cleanPath, expectedPrefix) {
		log.Printf("Permission denied: User '%s' attempted to download path '%s'", username, filePath)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(cleanPath)+"\"")
	http.ServeFile(w, r, cleanPath)
}

// --- Setup and Helper Functions ---
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

	if config.VisitLog != "" {
		logFile, err := os.OpenFile(config.VisitLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", config.VisitLog, err)
		}
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/delete", deleteHandler)
	mux.HandleFunc("/history", historyHandler)
	mux.HandleFunc("/download", downloadHandler)

	authHandler := basicAuth(mux)

	log.Printf("Server starting, listening on %s", config.Bind)
	if config.TLS {
		log.Println("TLS is enabled.")
		checkAndGenerateCerts()
		err := http.ListenAndServeTLS(config.Bind, config.CertFile, config.KeyFile, authHandler)
		if err != nil {
			log.Fatalf("Server startup failed: %v", err)
		}
	} else {
		log.Println("TLS is disabled, using plain HTTP.")
		err := http.ListenAndServe(config.Bind, authHandler)
		if err != nil {
			log.Fatalf("Server startup failed: %v", err)
		}
	}
}