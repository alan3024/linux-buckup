# Go SFTP 备份工具

这是一个使用 Go 语言和 Fyne 库构建的图形化 SFTP 备份工具。它允许用户通过一个简洁的界面，将远程服务器上的文件夹安全、高效地备份到本地。

![程序运行截图](https://github.com/alan3024/pic/blob/8f9f3d9beb2ec67dd788ff463bdf324f7dadb86f/go.png)
## ✨ 功能亮点
- **图形化界面**: 拥有一个简洁直观的图形用户界面，所有操作一目了然。
- **配置加密**: 服务器IP、用户名和密码等敏感信息使用 AES 算法加密后保存在 `config.json` 文件中，保障您的凭据安全。
- **增量备份**: 在后续备份中，能自动检测并跳过未发生变化的文件，只下载新增或被修改过的文件，极大地提升了备份效率。
- **实时进度条**: 在下载大文件时，会显示实时的下载进度条和文件名。
- **定时自动备份**: 支持按小时、天、周的频率进行后台自动备份。
- **跨平台运行**: 基于 Go 和 Fyne 构建，理论上可以编译运行在 Windows, macOS 和 Linux 等多个操作系统上。
- **系统托盘**: 关闭主窗口后，程序会最小化到系统托盘，方便在后台静默运行。
- **单实例锁定**: 程序启动时会创建锁文件，防止多个实例同时运行造成冲突。
- **打包图标**: 最终的可执行文件包含了自定义的应用程序图标。
---
## 🚀 如何运行

在运行此程序前，您需要先安装 Go 语言环境和一个C语言编译器。
#### 1. 环境准备

- **安装 Go**: 请从 [Go 语言官网](https://golang.org/) 下载并安装 Go。
- **安装 C 编译器**:
    - **Windows**: 安装 [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) 或 MinGW。
    - **macOS**: 安装 Xcode Command Line Tools (`xcode-select --install`)。
    - **Linux**: 安装 `gcc` (`sudo apt-get install build-essential` 或类似的命令)。

#### 2. 安装 Fyne 工具
程序依赖 Fyne 的命令行工具来打包资源文件。
```sh
go install fyne.io/fyne/v2/cmd/fyne@latest
```
#### 3. 克隆并运行
```sh
# 克隆仓库
git clone https://github.com/YOUR_USERNAME/go-sftp-backup.git
cd go-sftp-backup
# (可选) 准备图标文件
# 将您自己的 Icon.png 文件放入此目录
# 打包资源文件 (如图标)
fyne bundle -o bundled.go Icon.png
# 下载 Go 依赖项
go mod tidy
# 运行程序
go run .
```
#### 4. 编译为可执行文件
如果您想生成一个独立的可执行文件：
```sh
# 对于 Windows，使用 -ldflags 可以隐藏命令行窗口
go build -ldflags="-H windowsgui" -o backup-tool.exe .
```
---
## 🛠️ 主要依赖

- [Fyne](https://github.com/fyne-io/fyne): 一个用于 Go 语言的简单、易用的跨平台 GUI 工具包。
- [github.com/pkg/sftp](https://github.com/pkg/sftp): 一个纯 Go 实现的 SFTP 客户端。
- [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh): Go 官方的 SSH 客户端实现。
- [github.com/gofrs/flock](https://github.com/gofrs/flock): 用于文件锁，实现单实例运行。 
