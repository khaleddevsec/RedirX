package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"redirx/internal/logger"
	"redirx/pkg/version"
)

const (
	GitHubRepo       = "khaleddevsec/RedirX"
	LatestReleaseURL = "https://api.github.com/repos/" + GitHubRepo + "/releases/latest"
)

// GitHubRelease represents the GitHub release payload.
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Name    string        `json:"name"`
	Assets  []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a downloadable release file.
type GitHubAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
}

// CheckAndApplyUpdate inspects the upstream repository for updates and installs them safely.
func CheckAndApplyUpdate(ctx context.Context, backupDir string) error {
	logger.PrintInfo("Checking GitHub for the latest RedirX release...")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, LatestReleaseURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "RedirX-Updater/"+version.Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to contact GitHub release API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no release found on GitHub (%s)", LatestReleaseURL)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP %d from GitHub release API", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release metadata: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version.Version, "v")

	logger.PrintInfo("Current version: %s | Latest version: %s", currentVersion, latestVersion)

	if latestVersion == currentVersion {
		logger.PrintSuccess("RedirX is already up to date (%s)", version.Version)
		return nil
	}

	// Determine matching asset pattern for current OS and architecture
	expectedAssetPrefix := fmt.Sprintf("redirx_%s_%s", runtime.GOOS, runtime.GOARCH)
	var binaryAsset *GitHubAsset
	var checksumAsset *GitHubAsset

	for i := range release.Assets {
		a := &release.Assets[i]
		if strings.Contains(strings.ToLower(a.Name), "checksum") {
			checksumAsset = a
		} else if strings.Contains(strings.ToLower(a.Name), expectedAssetPrefix) {
			binaryAsset = a
		}
	}

	if binaryAsset == nil {
		return fmt.Errorf("no compatible release binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	logger.PrintInfo("Found compatible release asset: %s", binaryAsset.Name)

	// Fetch expected checksum if available
	var expectedChecksum string
	if checksumAsset != nil {
		logger.PrintInfo("Downloading checksums from %s...", checksumAsset.Name)
		checksums, err := downloadChecksums(ctx, client, checksumAsset.DownloadURL)
		if err == nil {
			expectedChecksum = checksums[binaryAsset.Name]
		}
	}

	// Download new binary to temporary file
	tmpFile, err := os.CreateTemp("", "redirx-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file for update: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	logger.PrintInfo("Downloading update from %s...", binaryAsset.DownloadURL)
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryAsset.DownloadURL, nil)
	if err != nil {
		_ = tmpFile.Close()
		return err
	}

	downloadResp, err := client.Do(downloadReq)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	defer downloadResp.Body.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, downloadResp.Body); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed saving downloaded update: %w", err)
	}
	_ = tmpFile.Close()

	computedHash := hex.EncodeToString(hasher.Sum(nil))

	// Verify SHA-256
	if expectedChecksum != "" {
		if !strings.EqualFold(computedHash, expectedChecksum) {
			return fmt.Errorf("checksum mismatch! Expected %s, got %s", expectedChecksum, computedHash)
		}
		logger.PrintSuccess("SHA-256 checksum verified: %s", computedHash)
	} else {
		logger.PrintWarn("Warning: No checksum file found in release. Proceeding with caution (hash: %s)", computedHash)
	}

	// Replace existing executable safely
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate running executable: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed resolving executable symlinks: %w", err)
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("cannot create backup directory: %w", err)
	}

	backupPath := filepath.Join(backupDir, fmt.Sprintf("redirx_%s_%d.bak", currentVersion, time.Now().Unix()))
	logger.PrintInfo("Backing up current executable to %s...", backupPath)

	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("backup failed, update aborted: %w", err)
	}

	// Replace binary atomically
	if err := replaceBinary(tmpPath, execPath); err != nil {
		logger.PrintError("Update failed during binary replacement: %v. Restoring backup...", err)
		_ = copyFile(backupPath, execPath)
		return fmt.Errorf("update failed and was rolled back: %w", err)
	}

	logger.PrintSuccess("Successfully updated RedirX to version %s!", release.TagName)
	return nil
}

func downloadChecksums(ctx context.Context, client *http.Client, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	sums := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hash := parts[0]
			name := filepath.Base(parts[1])
			sums[name] = hash
		}
	}

	return sums, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func replaceBinary(newBinary, targetPath string) error {
	// Ensure executable permissions
	if err := os.Chmod(newBinary, 0755); err != nil {
		return err
	}

	// On POSIX/Linux, os.Rename over an active binary performs an atomic inode swap.
	// On Windows, running binaries are locked, so renaming target to .old first allows it.
	if runtime.GOOS == "windows" {
		oldPath := targetPath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(targetPath, oldPath); err != nil {
			return err
		}
		if err := copyFile(newBinary, targetPath); err != nil {
			_ = os.Rename(oldPath, targetPath)
			return err
		}
		_ = os.Remove(oldPath)
		return nil
	}

	// Direct atomic rename for Linux
	return os.Rename(newBinary, targetPath)
}

var ErrNoUpdateAvailable = errors.New("no update available")

