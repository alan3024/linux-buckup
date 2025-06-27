package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/gofrs/flock"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// 这是一个固定的密钥，用于加密配置文件。
// 警告：如果此密钥丢失或更改，旧的配置文件将无法解密！
var encryptionKey = []byte("ThirtyTwoByteLongCryptoSecretKey")

// encrypt 使用 AES-GCM 加密数据
func encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt 使用 AES-GCM 解密数据
func decrypt(encodedData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// progressWriter 负责在数据写入时更新进度
type progressWriter struct {
	total    int64
	written  int64
	appState *AppState
}

// Write 实现了 io.Writer 接口
func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	pw.written += int64(n)
	if pw.total > 0 {
		percentage := float64(pw.written) / float64(pw.total)
		pw.appState.progressValue.Set(percentage)
	}
	return n, nil
}

const configFile = "config.json"

// Config 存储了所有的配置信息
type Config struct {
	Server            string    `json:"server"`
	Port              string    `json:"port"`
	User              string    `json:"user"`
	Password          string    `json:"password"`
	RemoteDir         string    `json:"remote_dir"`
	LocalDir          string    `json:"local_dir"`
	AutoBackupEnabled bool      `json:"auto_backup_enabled"`
	Frequency         string    `json:"frequency"` // "Hourly", "Daily", "Weekly"
	LastBackupTime    time.Time `json:"last_backup_time"`
}

// AppState 包含应用的状态和UI组件
type AppState struct {
	config            Config
	app               fyne.App
	win               fyne.Window
	logContent        binding.String
	mu                sync.Mutex
	progressContainer *fyne.Container
	progressValue     binding.Float
	progressLabel     binding.String
	schedulerTicker   *time.Ticker
	windowVisible     bool
}

func main() {
	// 实现单实例运行
	lockPath := filepath.Join(os.TempDir(), "sftp-backup.lock")
	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLock()
	if err != nil {
		// 如果创建锁文件本身失败，记录日志并退出
		log.Fatalf("无法创建锁文件: %v", err)
	}

	if !locked {
		// 如果锁定失败，说明已有实例在运行
		log.Println("程序已在运行中，无法重复打开。")
		// 可以在这里加一个弹窗，但为了简单起见，直接退出
		os.Exit(0)
	}
	// 确保程序退出时解锁
	defer fileLock.Unlock()

	a := app.New()
	a.SetIcon(resourceIconPng)
	win := a.NewWindow("SFTP 备份工具")

	appState := &AppState{
		app:           a,
		win:           win,
		logContent:    binding.NewString(),
		progressValue: binding.NewFloat(),
		progressLabel: binding.NewString(),
		windowVisible: true,
	}
	appState.logContent.Set("欢迎使用！请配置并开始备份。\n")
	appState.progressLabel.Set("...") // 初始文本

	// 设置系统托盘
	if desk, ok := a.(desktop.App); ok {
		menu := fyne.NewMenu("SFTP Backup",
			fyne.NewMenuItem("显示/隐藏", func() {
				if appState.windowVisible {
					appState.win.Hide()
					appState.windowVisible = false
				} else {
					appState.win.Show()
					appState.windowVisible = true
				}
			}))
		desk.SetSystemTrayMenu(menu)
		desk.SetSystemTrayIcon(theme.StorageIcon())
		appState.win.SetCloseIntercept(func() {
			appState.win.Hide()
			appState.windowVisible = false
		})
	}

	// 配置输入字段
	serverEntry := widget.NewEntry()
	portEntry := widget.NewEntry()
	userEntry := widget.NewEntry()
	passwordEntry := widget.NewPasswordEntry()
	remoteDirEntry := widget.NewEntry()
	localDirEntry := widget.NewEntry()

	// 自动备份UI
	enableCheck := widget.NewCheck("启用自动备份", func(b bool) {
		appState.config.AutoBackupEnabled = b
	})
	frequencySelect := widget.NewSelect([]string{"Hourly", "Daily", "Weekly"}, func(s string) {
		appState.config.Frequency = s
	})
	frequencySelect.PlaceHolder = "选择频率"

	// 新增：本地目录浏览按钮
	browseButton := widget.NewButton("浏览...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(err, appState.win)
				return
			}
			if uri != nil {
				localDirEntry.SetText(uri.Path())
			}
		}, appState.win)
	})

	// 加载初始配置
	if err := appState.loadConfig(); err != nil {
		appState.log(fmt.Sprintf("加载配置失败: %v。可能是首次运行，请配置。", err))
	}

	serverEntry.SetText(appState.config.Server)
	portEntry.SetText(appState.config.Port)
	userEntry.SetText(appState.config.User)
	passwordEntry.SetText(appState.config.Password)
	remoteDirEntry.SetText(appState.config.RemoteDir)
	localDirEntry.SetText(appState.config.LocalDir)
	enableCheck.SetChecked(appState.config.AutoBackupEnabled)
	frequencySelect.SetSelected(appState.config.Frequency)

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "服务器IP", Widget: serverEntry},
			{Text: "端口", Widget: portEntry},
			{Text: "用户名", Widget: userEntry},
			{Text: "密码", Widget: passwordEntry},
			{Text: "远程目录", Widget: remoteDirEntry},
			{Text: "本地目录", Widget: container.NewBorder(nil, nil, nil, browseButton, localDirEntry)},
			{Text: "自动备份", Widget: container.NewVBox(enableCheck, frequencySelect)},
		},
	}

	// 新增：进度条和标签
	progressLabelWidget := widget.NewLabelWithData(appState.progressLabel)
	progressBar := widget.NewProgressBarWithData(appState.progressValue)
	appState.progressContainer = container.NewVBox(progressLabelWidget, progressBar)
	appState.progressContainer.Hide() // 默认隐藏

	// 日志区域
	logLabel := widget.NewLabelWithData(appState.logContent)
	logLabel.Wrapping = fyne.TextWrapWord
	logContainer := container.NewScroll(logLabel)
	logContainer.SetMinSize(fyne.NewSize(0, 200))

	// 按钮
	saveButton := widget.NewButton("保存配置", func() {
		appState.mu.Lock()
		defer appState.mu.Unlock()

		appState.config.Server = serverEntry.Text
		appState.config.Port = portEntry.Text
		appState.config.User = userEntry.Text
		appState.config.Password = passwordEntry.Text
		appState.config.RemoteDir = remoteDirEntry.Text
		appState.config.LocalDir = localDirEntry.Text
		appState.config.AutoBackupEnabled = enableCheck.Checked
		appState.config.Frequency = frequencySelect.Selected

		if err := appState.saveConfig(); err != nil {
			dialog.ShowError(err, appState.win)
			appState.log(fmt.Sprintf("保存配置失败: %v", err))
		} else {
			dialog.ShowInformation("成功", "加密配置已保存！", appState.win)
			appState.log("配置已成功加密并保存到 config.json")
			appState.restartScheduler_unsafe() // 重启调度器以应用新配置
		}
	})

	resetButton := widget.NewButton("清空配置", func() {
		dialog.ShowConfirm("确认", "您确定要清空所有配置吗？此操作不可逆。", func(confirm bool) {
			if !confirm {
				return
			}
			serverEntry.SetText("")
			portEntry.SetText("")
			userEntry.SetText("")
			passwordEntry.SetText("")
			remoteDirEntry.SetText("")
			localDirEntry.SetText("")
			enableCheck.SetChecked(false)
			frequencySelect.ClearSelected()

			appState.mu.Lock()
			defer appState.mu.Unlock()
			appState.config = Config{} // 清空内存中的配置
			os.Remove(configFile)      // 删除配置文件
			appState.log("配置已清空。")
			appState.stopScheduler_unsafe()
		}, appState.win)
	})

	exitButton := widget.NewButton("退出程序", func() {
		a.Quit()
	})

	backupButton := widget.NewButton("立即备份", func() {
		// 保存一次当前界面上的配置，以防用户修改后未保存就点击备份
		appState.mu.Lock()
		appState.config.Server = serverEntry.Text
		appState.config.Port = portEntry.Text
		appState.config.User = userEntry.Text
		appState.config.Password = passwordEntry.Text
		appState.config.RemoteDir = remoteDirEntry.Text
		appState.config.LocalDir = localDirEntry.Text
		appState.mu.Unlock()

		appState.clearLogs()
		appState.log("手动备份任务已启动...")
		go appState.runBackup()
	})

	// 布局
	centerContent := container.NewVBox(appState.progressContainer, logContainer)
	content := container.NewBorder(
		form,
		container.NewGridWithRows(2,
			container.NewGridWithColumns(2, saveButton, backupButton),
			container.NewGridWithColumns(2, resetButton, exitButton),
		),
		nil,
		nil,
		centerContent,
	)

	win.SetContent(content)
	win.Resize(fyne.NewSize(600, 500))
	appState.startScheduler() // 启动时开启调度器
	win.ShowAndRun()
}

func (app *AppState) loadConfig() error {
	app.mu.Lock()
	defer app.mu.Unlock()
	file, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在是正常情况
		}
		return err
	}
	if len(file) == 0 {
		return nil // 文件是空的
	}

	decryptedData, err := decrypt(string(file), encryptionKey)
	if err != nil {
		return fmt.Errorf("解密失败，配置文件可能已损坏或来自不兼容的版本: %w", err)
	}

	return json.Unmarshal(decryptedData, &app.config)
}

func (app *AppState) saveConfig() error {
	// 调用此函数前必须获取锁
	data, err := json.MarshalIndent(app.config, "", "    ")
	if err != nil {
		return err
	}

	encryptedData, err := encrypt(data, encryptionKey)
	if err != nil {
		return fmt.Errorf("加密配置失败: %w", err)
	}

	return os.WriteFile(configFile, []byte(encryptedData), 0644)
}

func (app *AppState) log(message string) {
	log.Println(message) // 保留控制台日志
	currentLog, _ := app.logContent.Get()

	if strings.HasPrefix(currentLog, "欢迎使用") {
		currentLog = ""
	}
	newLog := currentLog + time.Now().Format("15:04:05") + ": " + message + "\n"
	app.logContent.Set(newLog)
}

func (app *AppState) clearLogs() {
	app.logContent.Set("")
}

func (app *AppState) runBackup() {
	cfg := app.config

	// SSH 客户端配置
	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 连接 SSH
	addr := fmt.Sprintf("%s:%s", cfg.Server, cfg.Port)
	app.log(fmt.Sprintf("正在连接到 %s...", addr))
	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		app.log(fmt.Sprintf("SSH 连接失败: %v", err))
		dialog.ShowError(err, app.win)
		return
	}
	defer conn.Close()
	app.log("SSH 连接成功!")

	// 创建 SFTP 客户端
	client, err := sftp.NewClient(conn)
	if err != nil {
		app.log(fmt.Sprintf("无法创建 SFTP 客户端: %v", err))
		dialog.ShowError(err, app.win)
		return
	}
	defer client.Close()
	app.log("SFTP 客户端创建成功!")

	// 开始备份
	app.log(fmt.Sprintf("开始备份远程目录 '%s' 到本地 '%s'", cfg.RemoteDir, cfg.LocalDir))
	err = app.downloadDirectory(client, cfg.RemoteDir, cfg.LocalDir)
	if err != nil {
		finalMessage := fmt.Sprintf("备份失败: %v", err)
		app.log(finalMessage)
		dialog.ShowError(err, app.win)
	} else {
		finalMessage := "备份成功完成!"
		app.log(finalMessage)
		dialog.ShowInformation("成功", finalMessage, app.win)

		// 更新最后备份时间并保存
		app.mu.Lock()
		app.config.LastBackupTime = time.Now()
		app.saveConfig()
		app.mu.Unlock()
	}
}

// downloadDirectory 递归下载整个目录
func (app *AppState) downloadDirectory(client *sftp.Client, remoteDir, localDir string) error {
	if err := os.MkdirAll(localDir, os.ModePerm); err != nil {
		return fmt.Errorf("无法创建本地目录 '%s': %w", localDir, err)
	}

	files, err := client.ReadDir(remoteDir)
	if err != nil {
		return fmt.Errorf("无法读取远程目录 '%s': %w", remoteDir, err)
	}

	for _, file := range files {
		// 修正：为远程路径使用正确的路径分隔符
		remotePath := path.Join(remoteDir, file.Name())
		localPath := filepath.Join(localDir, file.Name())

		if file.IsDir() {
			app.log(fmt.Sprintf("正在进入目录: %s", remotePath))
			if err := app.downloadDirectory(client, remotePath, localPath); err != nil {
				return err
			}
		} else {
			if err := app.downloadFile(client, remotePath, localPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// downloadFile 下载单个文件，支持增量备份
func (app *AppState) downloadFile(client *sftp.Client, remoteFile, localFile string) error {
	// 1. 获取远程文件信息
	remoteStat, err := client.Stat(remoteFile)
	if err != nil {
		return fmt.Errorf("无法获取远程文件 '%s' 的信息: %w", remoteFile, err)
	}

	// 2. 检查本地文件并进行比较
	localStat, err := os.Stat(localFile)
	if err == nil {
		// 如果本地文件存在，比较大小和修改时间
		if localStat.Size() == remoteStat.Size() && !localStat.ModTime().Before(remoteStat.ModTime()) {
			app.log(fmt.Sprintf("文件未变动，跳过: %s", filepath.Base(remoteFile)))
			return nil // 文件相同，跳过下载
		}
	}

	app.log(fmt.Sprintf("正在下载文件: %s -> %s", remoteFile, localFile))

	// 显示并重置进度条
	app.progressLabel.Set(fmt.Sprintf("下载中: %s", filepath.Base(remoteFile)))
	app.progressValue.Set(0)
	app.progressContainer.Show()
	defer app.progressContainer.Hide() // 确保下载结束后隐藏

	// 打开远程文件
	srcFile, err := client.Open(remoteFile)
	if err != nil {
		return fmt.Errorf("无法打开远程文件 '%s': %w", remoteFile, err)
	}
	defer srcFile.Close()

	// 创建本地文件
	dstFile, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("无法创建本地文件 '%s': %w", localFile, err)
	}

	// 使用 TeeReader 来包装源文件，并附带我们的进度写入器
	pw := &progressWriter{total: remoteStat.Size(), appState: app}
	reader := io.TeeReader(srcFile, pw)

	// 拷贝文件内容，同时进度会被更新
	_, err = io.Copy(dstFile, reader)
	// 必须先关闭文件，才能进行后续操作
	dstFile.Close()

	if err != nil {
		os.Remove(localFile) // 尝试清理下载失败的残留文件
		return fmt.Errorf("无法拷贝文件内容从 '%s' 到 '%s': %w", remoteFile, localFile, err)
	}

	// 成功下载后，将本地文件的修改时间设置为与远程文件一致
	err = os.Chtimes(localFile, time.Now(), remoteStat.ModTime())
	if err != nil {
		// 这是一个非致命错误，只记录日志
		app.log(fmt.Sprintf("警告: 无法更新文件修改时间 '%s': %v", localFile, err))
	}

	return nil
}

func (app *AppState) startScheduler() {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.startScheduler_unsafe()
}

// startScheduler_unsafe 启动调度器，假定调用方已持有锁
func (app *AppState) startScheduler_unsafe() {
	if app.schedulerTicker != nil {
		app.schedulerTicker.Stop()
	}

	if !app.config.AutoBackupEnabled || app.config.Frequency == "" {
		app.log("自动备份未启用，调度器未启动。")
		return
	}

	var duration time.Duration
	switch app.config.Frequency {
	case "Hourly":
		duration = time.Hour
	case "Daily":
		duration = 24 * time.Hour
	case "Weekly":
		duration = 7 * 24 * time.Hour
	default:
		app.log(fmt.Sprintf("未知的备份频率 '%s'，调度器未启动。", app.config.Frequency))
		return
	}

	app.log(fmt.Sprintf("调度器已启动，备份频率: %s", app.config.Frequency))
	// 每10分钟检查一次是否需要备份
	app.schedulerTicker = time.NewTicker(10 * time.Minute)

	go func() {
		for range app.schedulerTicker.C {
			app.mu.Lock()
			lastBackup := app.config.LastBackupTime
			needsBackup := time.Since(lastBackup) > duration
			app.mu.Unlock()

			if needsBackup {
				app.log("定时任务触发，开始自动备份...")
				app.runBackup()
			}
		}
	}()
}

func (app *AppState) stopScheduler() {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.stopScheduler_unsafe()
}

// stopScheduler_unsafe 停止调度器，假定调用方已持有锁
func (app *AppState) stopScheduler_unsafe() {
	if app.schedulerTicker != nil {
		app.schedulerTicker.Stop()
		app.schedulerTicker = nil
		app.log("调度器已停止。")
	}
}

func (app *AppState) restartScheduler() {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.restartScheduler_unsafe()
}

// restartScheduler_unsafe 重启调度器，假定调用方已持有锁
func (app *AppState) restartScheduler_unsafe() {
	app.stopScheduler_unsafe()
	app.startScheduler_unsafe()
}
