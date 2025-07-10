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
	"strings"
	"time"
	_ "embed"
)

//go:embed index.html
var indexHTML []byte

type Config struct {
	Bind      string `json:"bind"`
	TLS       bool   `json:"tls"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	VisitLog  string `json:"visit_log"`
	DataDir   string `json:"data_dir"`
	UsersFile string `json:"users_file"`
}

// 定义一个自定义类型作为 context 的 key，防止与其他包的 key 冲突
type contextKey string
const userContextKey = contextKey("username")

var config Config
var users = make(map[string]string)
const defaultConfigPath = "config.json"

// loadConfig 加载或创建配置文件
func loadConfig() {
	defaultConfig := Config{
		Bind:      ":8094",
		TLS:       true,
		CertFile:  "cert.pem",
		KeyFile:   "key.pem",
		VisitLog:  "visit.log",
		DataDir:   "data",
		UsersFile: "users.txt",
	}

	if _, err := os.Stat(defaultConfigPath); os.IsNotExist(err) {
		log.Printf("未找到配置文件 %s，正在创建默认配置...", defaultConfigPath)
		file, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			log.Fatalf("无法编码默认配置: %v", err)
		}
		if err := os.WriteFile(defaultConfigPath, file, 0644); err != nil {
			log.Fatalf("无法写入默认配置文件: %v", err)
		}
		config = defaultConfig
	} else {
		file, err := os.ReadFile(defaultConfigPath)
		if err != nil {
			log.Fatalf("无法读取配置文件: %v", err)
		}
		if err := json.Unmarshal(file, &config); err != nil {
			log.Fatalf("无法解析配置文件: %v", err)
		}
		log.Printf("成功加载配置文件 %s", defaultConfigPath)
	}

	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		log.Fatalf("无法创建数据目录 %s: %v", config.DataDir, err)
	}
}

// generateRandomPassword 生成一个安全的随机密码
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

// loadUsers 加载或创建用户文件
func loadUsers() {
	if _, err := os.Stat(config.UsersFile); os.IsNotExist(err) {
		log.Printf("未找到用户文件 %s，正在创建默认用户 'admin'...", config.UsersFile)
		password, err := generateRandomPassword(12)
		if err != nil {
			log.Fatalf("无法生成随机密码: %v", err)
		}
		content := fmt.Sprintf("admin:%s\n", password)
		if err := os.WriteFile(config.UsersFile, []byte(content), 0600); err != nil {
			log.Fatalf("无法写入用户文件: %v", err)
		}
		log.Println("=======================================================")
		log.Printf("默认用户已创建:")
		log.Printf("  用户名: admin")
		log.Printf("  密  码: %s", password)
		log.Println("请妥善保管此密码！")
		log.Println("=======================================================")
	}

	content, err := os.ReadFile(config.UsersFile)
	if err != nil {
		log.Fatalf("无法读取用户文件 %s: %v", config.UsersFile, err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			log.Printf("警告: 用户文件中有无效行: %s", line)
			continue
		}
		users[parts[0]] = parts[1]
	}
	if len(users) == 0 {
		log.Fatal("用户文件中未找到任何有效用户。")
	}
	log.Printf("成功加载 %d 个用户。", len(users))
}

// checkAndGenerateCerts 检查证书是否存在，如果不存在则生成自签名证书
func checkAndGenerateCerts() {
	if _, err := os.Stat(config.CertFile); !os.IsNotExist(err) {
		if _, err := os.Stat(config.KeyFile); !os.IsNotExist(err) {
			log.Printf("找到现有证书: %s, %s", config.CertFile, config.KeyFile)
			return
		}
	}

	log.Printf("未找到证书，正在生成新的自签名证书...")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("无法生成RSA私钥: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10年有效期

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("无法生成序列号: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mobile Upload Self-Signed"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 添加IP地址和DNS名称，使证书对本地网络有效
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	template.DNSNames = append(template.DNSNames, "localhost")
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					template.IPAddresses = append(template.IPAddresses, ipnet.IP)
				}
			}
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("无法创建证书: %v", err)
	}

	// 写入 cert.pem
	certOut, err := os.Create(config.CertFile)
	if err != nil {
		log.Fatalf("无法创建 %s: %v", config.CertFile, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Printf("已生成证书文件: %s", config.CertFile)

	// 写入 key.pem
	keyOut, err := os.OpenFile(config.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("无法创建 %s: %v", config.KeyFile, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Printf("已生成密钥文件: %s", config.KeyFile)
}

// basicAuth 中间件，用于HTTP Basic认证，并将用户名注入context
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if storedPass, userOk := users[user]; userOk && storedPass == pass {
			// 认证成功，将用户名存入 context
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			log.Printf("认证失败: 用户名或密码错误, user=%s, from=%s", user, r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

// rootHandler 处理根路径，返回HTML页面
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// uploadHandler 处理文件上传
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 context 中获取用户名
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		log.Println("上传错误: 无法从 context 获取用户名")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	r.ParseMultipartForm(1 << 30) // 限制上传大小为 1GB

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("上传错误: 无法获取文件: %v", err)
		http.Error(w, "Invalid file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 创建 用户名/日期 子目录
	dateDir := time.Now().Format("2006-01-02")
	uploadPath := filepath.Join(config.DataDir, username, dateDir)
	if err := os.MkdirAll(uploadPath, 0755); err != nil {
		log.Printf("上传错误: 无法创建目录 %s: %v", uploadPath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	safeFilename := filepath.Base(handler.Filename)
	destPath := filepath.Join(uploadPath, safeFilename)
	log.Printf("用户 '%s' 接收到文件: %s, 保存到: %s", username, handler.Filename, destPath)

	destFile, err := os.Create(destPath)
	if err != nil {
		log.Printf("上传错误: 无法创建目标文件 %s: %v", destPath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, file); err != nil {
		log.Printf("上传错误: 无法写入文件内容到 %s: %v", destPath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// 返回成功信息和文件路径
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// 使用 ToSlash 确保路径分隔符为 '/', 兼容web
	relativePath := filepath.ToSlash(destPath)
	json.NewEncoder(w).Encode(map[string]string{"filePath": relativePath})
}

// deleteHandler 处理文件删除请求
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 context 获取当前登录的用户名
	username, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		log.Println("删除错误: 无法从 context 获取用户名")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 解析请求体中的 JSON
	var payload struct {
		FilePath string `json:"filePath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 安全性校验：确保用户只能删除自己目录下的文件
	// 将 web 路径分隔符'/'转为系统分隔符
	cleanPath := filepath.FromSlash(filepath.Clean(payload.FilePath))
	parts := strings.Split(cleanPath, string(os.PathSeparator))
	
	// 期望的路径结构: data_dir, username, date, filename
	if len(parts) < 3 || parts[0] != config.DataDir || parts[1] != username {
		log.Printf("删除权限错误: 用户 '%s' 尝试删除路径 '%s'", username, payload.FilePath)
		http.Error(w, "Forbidden: You can only delete your own files.", http.StatusForbidden)
		return
	}

	// 执行删除
	err := os.Remove(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件已经不存在，也视为成功，因为目标已达成
			log.Printf("文件已不存在，删除操作完成: %s", cleanPath)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "File already deleted"})
			return
		}
		// 其他删除错误
		log.Printf("删除文件时出错 %s: %v", cleanPath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("用户 '%s' 成功删除文件: %s", username, cleanPath)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "File deleted successfully"})
}


func main() {
	log.Println("https://github.com/kikoqiu/gofileup")
	loadConfig()
	loadUsers()

	if config.VisitLog != "" {
		logFile, err := os.OpenFile(config.VisitLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("无法打开日志文件 %s: %v", config.VisitLog, err)
		}
		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/delete", deleteHandler) // 新增删除路由
	
	authHandler := basicAuth(mux)

	log.Printf("服务器正在启动，监听地址: %s", config.Bind)
	if config.TLS {
		log.Println("TLS 已启用。")
		checkAndGenerateCerts() // 检查或生成证书
		err := http.ListenAndServeTLS(config.Bind, config.CertFile, config.KeyFile, authHandler)
		if err != nil {
			log.Fatalf("服务器启动失败: %v", err)
		}
	} else {
		log.Println("TLS 已禁用，使用普通HTTP。")
		err := http.ListenAndServe(config.Bind, authHandler)
		if err != nil {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}
}