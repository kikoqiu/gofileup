# Go 手机临时文件上传助手

一个轻量、自托管的Web应用，旨在让您通过局域网，像使用即时通讯（IM）软件一样，轻松地将手机上的临时文件、图片和文本片段上传到您的电脑，并支持多设备间消息同步。

---

## 简体中文

### ✨ 功能亮点

- **现代化的IM界面**: 采用类似主流IM的聊天界面，直观易用。
- **多种上传方式**:
  - **文件上传**: 支持上传任意类型的文件。
  - **图片上传**: 专门的图片选择器，方便快速分享截图或照片。
  - **文本发送**: 文本框中输入的内容将被保存为`.txt`文件上传，文件名根据内容和时间智能生成。
- **跨设备同步**: 在任何设备上上传的文件，都会出现在其他设备的聊天记录中（通过刷新）。
- **实时进度与反馈**: 文件上传时显示实时进度条，成功后绿色高亮提示。
- **安全可靠**:
  - **HTTPS/TLS加密**: 默认启用TLS，并能**自动生成自签名证书**。
  - **用户认证**: 采用HTTP Basic Auth进行身份验证。
  - **用户隔离**: 每个用户的文件和历史记录都存储在自己独立的目录下。
- **智能管理**:
  - **自动配置**: 首次启动时自动生成`config.json`配置文件、`users.txt`用户文件，以及本`README.md`说明文件。
  - **文件整理**: 文件自动按 `data/用户名/年-月-日/` 的结构存放。
  - **消息持久化**: 聊天记录保存在浏览器本地存储中，并与服务器7天内的历史记录同步。
- **强大的文件操作**:
  - **文件下载与撤回**: 支持下载任意设备上传的文件，或撤回自己上传的文件。
- **纯粹与便携**:
  - **单文件部署**: 前端界面和说明文档通过`embed`方式嵌入Go程序，整个应用就是一个**独立的可执行文件**。
  - **跨平台**: Go语言编写，可轻松编译为Windows, macOS, Linux等多个平台的版本。
  - **国际化(i18n)**: 界面支持中/英文，根据浏览器语言自动切换。

### 🚀 快速开始

#### 1. 环境准备
- 安装 [Go 语言环境](https://golang.org/dl/) (版本 >= 1.16)。

#### 2. 获取并运行
- **下载或克隆代码**:
  ```bash
  git clone https://github.com/kikoqiu/gofileup.git
  cd gofileup
  ```
- **直接运行**:
  ```bash
  go run .
  ```
- **首次运行**:
  程序启动时会自动检测并创建所需文件。你将在控制台看到类似如下的输出（日志为英文）：
  ```
  Config file 'config.json' not found, creating default...
  User file 'users.txt' not found, creating default user 'admin'...
  =======================================================
  Default user created:
    Username: admin
    Password: AbCd1234EfGh  <-- 这是一个随机生成的密码
  Please store this password securely!
  =======================================================
  README.md not found, generating one...
  Certificate not found, generating new self-signed certificate...
  Server starting, listening on :8094
  ```

#### 3. 在手机上使用
1.  **获取电脑IP**: 在电脑终端或命令提示符中输入 `ipconfig` (Windows) 或 `ifconfig` / `ip a` (macOS/Linux)。
2.  **手机访问**: 打开手机浏览器，访问 `https://<你的电脑IP>:8094` (例如: `https://192.168.1.10:8094`)。
3.  **信任证书**: 浏览器会提示“不安全”。请点击“高级”->“继续前往”。
4.  **登录**: 输入控制台打印的用户名（`admin`）和随机密码。
5.  **开始使用**: 点击刷新按钮同步历史消息，或开始上传新文件。

### 🛠️ 构建可执行文件

项目提供了构建脚本 `build.all.bat` (Windows, 全平台)。双击运行即可生成独立的、可直接分发的可执行文件。

### ⚙️ 配置说明

#### `config.json`
```json
{
  "bind": ":8094",        // 监听的地址和端口
  "tls": true,            // 是否启用HTTPS
  "cert_file": "cert.pem",// 证书文件路径
  "key_file": "key.pem",  // 私钥文件路径
  "visit_log": "visit.log", // 访问日志文件
  "data_dir": "data",     // 上传文件的根目录
  "users_file": "users.txt" // 用户凭据文件
}
```

#### `users.txt`
格式: `用户名:密码`，每行一个。
```
# 这是注释行
admin:AbCd1234EfGh
user2:another_strong_password
```

### 💻 技术栈

- **后端**: Go (`net/http`, `embed`)
- **前端**: 原生 JavaScript (ES6+), HTML5, CSS3

### 📜 许可证

本项目采用 [MIT](https://opensource.org/licenses/MIT) 许可证。


---

## English

### ✨ Features

- **Modern IM Interface**: Intuitive and easy to use, resembling popular IM applications.
- **Multiple Upload Methods**:
  - **File Upload**: Supports any file type.
  - **Image Upload**: A dedicated image picker for quickly sharing screenshots or photos.
  - **Text Snippets**: Text entered in the input box is saved as a `.txt` file, with a filename intelligently generated from its content and timestamp.
- **Cross-Device Sync**: Files uploaded from any device will appear in the chat history of other devices after a refresh.
- **Real-time Feedback**: Live progress bars for file uploads with success/failure indicators.
- **Secure & Reliable**:
  - **HTTPS/TLS Encryption**: Enabled by default, with **auto-generated self-signed certificates**.
  - **User Authentication**: Uses HTTP Basic Auth to protect your data.
  - **User Isolation**: Each user's files and history are stored in separate, private directories.
- **Intelligent Management**:
  - **Auto-Configuration**: Automatically generates `config.json`, `users.txt`, and this `README.md` file on first launch.
  - **File Organization**: Files are automatically stored in a `data/username/YYYY-MM-DD/` structure.
  - **Message Persistence**: Chat history is saved in the browser's LocalStorage and synchronized with the server's 7-day history.
- **Powerful File Operations**:
  - **Download & Withdraw**: Download any file from the history, or withdraw (delete from server) files you've uploaded.
- **Pure & Portable**:
  - **Single-File Deployment**: The frontend UI and this README are embedded into the Go program, resulting in a **single, dependency-free executable**.
  - **Cross-Platform**: Written in Go, easily compiled for Windows, macOS, Linux, etc.
  - **Internationalization (i18n)**: The interface supports English and Chinese, automatically selected based on browser language.

### 🚀 Quick Start

#### 1. Prerequisites
- Install the [Go Environment](https://golang.org/dl/) (version >= 1.16).

#### 2. Get and Run
- **Download or clone the code**:
  ```bash
  git clone https://github.com/kikoqiu/gofileup.git
  cd gofileup
  ```
- **Run directly**:
  ```bash
  go run .
  ```
- **On First Run**:
  The program will automatically create necessary files. You will see output similar to this in your console:
  ```
  Config file 'config.json' not found, creating default...
  User file 'users.txt' not found, creating default user 'admin'...
  =======================================================
  Default user created:
    Username: admin
    Password: AbCd1234EfGh  <-- This is a randomly generated password
  Please store this password securely!
  =======================================================
  README.md not found, generating one...
  Certificate not found, generating new self-signed certificate...
  Server starting, listening on :8094
  ```

#### 3. Use on Your Phone
1.  **Get your Computer's IP**: Open a terminal/command prompt and type `ipconfig` (Windows) or `ifconfig` / `ip a` (macOS/Linux).
2.  **Access from Phone**: Open your phone's browser and navigate to `https://<YOUR_COMPUTER_IP>:8094` (e.g., `https://192.168.1.10:8094`).
3.  **Trust the Certificate**: Your browser will show a security warning. Click "Advanced" -> "Proceed to..." to accept the self-signed certificate.
4.  **Log In**: Use the username (`admin`) and random password printed in the console.
5.  **Start Transferring**: Click the refresh button to sync history, or start uploading new files.

### 🛠️ Build

The project includes build scripts `build.all.bat` (for all platforms, on Windows). Simply double-click to run them and generate standalone executables.

### ⚙️ Configuration

#### `config.json`
```json
{
  "bind": ":8094",        // Listen address and port
  "tls": true,            // Enable HTTPS (true/false)
  "cert_file": "cert.pem",// Certificate file path
  "key_file": "key.pem",  // Private key file path
  "visit_log": "visit.log", // Access log file
  "data_dir": "data",     // Root directory for uploaded files
  "users_file": "users.txt" // User credentials file
}
```

#### `users.txt`
Format: `username:password`, one per line.
```
# This is a comment line
admin:AbCd1234EfGh
user2:another_strong_password
```

### 💻 Tech Stack

- **Backend**: Go (`net/http`, `embed`)
- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3

### 📜 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
```