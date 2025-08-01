// 将json结果适配漏扫模块能方便入库的格式
package plugin

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/global"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/options"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/utils"
)

func GetName() string {
	return "AI-Infra-Guard"
}

func Install() error {
	toolPath := filepath.Join(global.ExtDir, "AI-Infra-Guard")
	if err := os.MkdirAll(toolPath, os.ModePerm); err != nil {
		logger.SlogError(fmt.Sprintf("Failed to create AI-Infra-Guard folder: %v", err))
		return err
	}
	osType := runtime.GOOS
	var downloadURL string
	var fileName string
	switch osType {
	case "windows":
		downloadURL = "https://github.com/Autumn-27/AI-Infra-Guard/releases/download/v0.0.5/AI-Infra-Guard_0.0.5_windows_amd64.zip"
		fileName = "ai-infra-guard.exe"
	case "linux":
		// 自己进行编译处理给一个下载链接
		downloadURL = "https://github.com/yjy123123/AI-Infra-Guard/releases/download/v2.6.0/AI-Infra-Guard_2.6_linux.zip"
		fileName = "ai-infra-guard"
	}
	toolExecPath := filepath.Join(toolPath, fileName)
	if _, err := os.Stat(toolExecPath); os.IsNotExist(err) {
		// 创建目标目录、结果目录
		os.MkdirAll(filepath.Join(toolPath, "target"), os.ModePerm)
		os.MkdirAll(filepath.Join(toolPath, "result"), os.ModePerm)
		downloadPath := filepath.Join(global.ExtDir, "AI-Infra-Guard", "AI-Infra-Guard.zip") // 临时下载路径
		success, err := utils.Tools.HttpGetDownloadFile(downloadURL, downloadPath)
		if err != nil || !success {
			logger.SlogErrorLocal(fmt.Sprintf("Failed to download AI-Infra-Guard: %v", err))
			return err
		}

		logger.SlogInfo("AI-Infra-Guard Download successful")

		err = Unzip(downloadPath, toolPath)
		if err != nil {
			logger.SlogError(fmt.Sprintf("Failed to extract AI-Infra-Guard: %v", err))
			return err
		}
		switch osType {
		case "linux":
			err = os.Chmod(toolExecPath, 0755)
			if err != nil {
				logger.SlogError(fmt.Sprintf("Failed to set permissions: %v", err))
				return err
			}
		}
		defer utils.Tools.DeleteFile(downloadPath)
		logger.SlogInfo("AI-Infra-Guard installed successfully")
	}
	return nil
}

func Unzip(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func Check() error {
	return nil
}

// 增加卸载功能，便于后续更新迭代
func Uninstall() error {

	toolPath := filepath.Join(global.ExtDir, "AI-Infra-Guard")

	// 删除整个 AI-Infra-Guard 目录
	if err := os.RemoveAll(toolPath); err != nil {
		logger.SlogError(fmt.Sprintf("Failed to remove AI-Infra-Guard folder: %v", err))
		return err
	}

	logger.SlogInfo("AI-Infra-Guard uninstalled successfully")
	return nil
}

type HttpResult struct {
	URL           string       `json:"url"`            // Target URL
	Title         string       `json:"title"`          // Page title
	ContentLength int          `json:"content-length"` // Response content length
	StatusCode    int          `json:"status-code"`    // HTTP status code
	ResponseTime  string       `json:"response-time"`  // Request response time
	Fingers       []FpResult   `json:"fingerprints"`   // Fingerprint detection results
	Advisories    []VersionVul `json:"advisories"`     // Vulnerability advisory information
	s             string       // Internal string representation
}

// 一个漏洞是一条数据
type VulnerabilityResult struct {
	TargetURL      string   `json:"target_url"`
	StatusCode     int      `json:"status_code"`
	Title          string   `json:"title"`
	Fingerprint    string   `json:"fingerprint"`
	CVE            string   `json:"cve"`
	Severity       string   `json:"severity"`
	Summary        string   `json:"summary"`
	Details        string   `json:"details"`
	SecurityAdvise string   `json:"security_advise"`
	References     []string `json:"references"`
}

type FpResult struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
}

type VersionVul struct {
	Info       Info     `yaml:"info"`       // Basic vulnerability information
	Rule       string   `yaml:"rule"`       // Rule expression in string format
	References []string `yaml:"references"` // Reference links
}

type Info struct {
	FingerPrintName string `yaml:"name"`                      // Name of the fingerprint
	CVEName         string `yaml:"cve"`                       // CVE identifier
	Summary         string `yaml:"summary"`                   // Brief summary of the vulnerability
	Details         string `yaml:"details"`                   // Detailed description
	CVSS            string `yaml:"cvss"`                      // CVSS score
	Severity        string `yaml:"severity"`                  // Severity level
	SecurityAdvise  string `yaml:"security_advise,omitempty"` // Security advisory
}

func Execute(input interface{}, op options.PluginOption) (interface{}, error) {
	targets := ""
	switch a := input.(type) {
	case []types.AssetOther:
		return nil, nil
	case []types.AssetHttp:
		for _, assetHttp := range a {
			targets += assetHttp.URL + "\n"
		}
	default:
		return nil, nil
	}
  
  
  
	toolPath := filepath.Join(global.ExtDir, "AI-Infra-Guard")
	scanId := utils.Tools.GenerateRandomString(6)
	osType := runtime.GOOS
	var fileName string
	switch osType {
	case "windows":
		fileName = "ai-infra-guard.exe"
	case "linux":
		fileName = "ai-infra-guard"
	}
	targetPath := filepath.Join(toolPath, "target", scanId)
	resultPath := filepath.Join(toolPath, "result", scanId)
	vulDir := filepath.Join(toolPath, "data", "vuln")
	fingerDir := filepath.Join(toolPath, "data", "fingerprints")
	err := utils.Tools.WriteContentFile(targetPath, targets)
	if err != nil {
		op.Log(fmt.Sprintf("write target error: %v", err))
		return nil, err
	}
	start := time.Now()
	defer utils.Tools.DeleteFile(targetPath)
	defer utils.Tools.DeleteFile(resultPath)
	exePath := filepath.Join(toolPath, fileName)
	//  --fps --vul 为必须携带的参数
    args := []string{"scan","--file", targetPath, "--output", resultPath, "--json", "--fps", fingerDir, "--vul", vulDir}
	
  
  // 使用有超时时间以及上下文管理的命令执行 方便处理异常以及适配暂停任务
	err = utils.Tools.ExecuteCommandWithTimeout(exePath, args, time.Duration(10)*time.Minute, op.Ctx)
	if err != nil {
		op.Log(fmt.Sprintf("ExecuteCommandWithTimeout error: %v", err), "w")
		return nil, err
	}
	resultChan := make(chan string)
	go utils.Tools.ReadFileLineByLine(resultPath, resultChan, op.Ctx)
	for result := range resultChan {
		if result != "" {
			var vulnResult VulnerabilityResult // 使用新定义的结构体
			err := json.Unmarshal([]byte(result), &vulnResult)
			if err != nil {
				op.Log(fmt.Sprintf("result to json error: %v %v", err, result), "w")
				continue
			}

			// 直接使用解析出的漏洞信息创建 VulnResult，VulnId避免去重被清除
			tmp := types.VulnResult{
				Url:     vulnResult.TargetURL,
				VulName: vulnResult.CVE ,
        VulnId:  vulnResult.Fingerprint +"-" +vulnResult.CVE,
				Matched: vulnResult.TargetURL,
				Level:   strings.ToLower(vulnResult.Severity),
				Time:    utils.Tools.GetTimeNow(),
				Request: result, 
				Status:  1,
				Tags:    []string{"AI-Infra-Guard"},
			}
			op.Log(fmt.Sprintf("found vul: %v %v", tmp.Url, tmp.VulName))
			op.ResultFunc(tmp)
		}
	}
	end := time.Now()
	duration := end.Sub(start)
	op.Log(fmt.Sprintf("AI-Infra-Guard scan completed, time: %v", duration))
	return nil, nil
}
