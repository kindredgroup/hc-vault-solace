package solace

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SolaceContainer holds the container and connection info for tests
type SolaceContainer struct {
	Container  testcontainers.Container
	Host       string // hostname:port for SEMP API
	AdminUser  string
	AdminPwd   string
	SEMPPort   int
	DisableTLS bool
}

// isDockerAvailable checks if Docker/Podman is available for testcontainers
func isDockerAvailable() bool {
	// Check DOCKER_HOST environment variable first (works on all platforms)
	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		return true
	}

	// Check TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE
	if override := os.Getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE"); override != "" {
		return true
	}

	// Platform-specific checks
	if isWindowsDockerAvailable() {
		return true
	}

	return isUnixDockerAvailable()
}

// isWindowsDockerAvailable checks for Docker Desktop named pipe on Windows
func isWindowsDockerAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Docker Desktop on Windows uses a named pipe
	pipePath := `\\.\pipe\docker_engine`
	if _, err := os.Stat(pipePath); err == nil {
		return true
	}

	return false
}

// isUnixDockerAvailable checks for Docker/Podman sockets on Unix systems
func isUnixDockerAvailable() bool {
	if runtime.GOOS == "windows" {
		return false
	}

	// Check common Docker socket locations
	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/podman/podman.sock",
	}

	// Also check XDG_RUNTIME_DIR for rootless podman
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		socketPaths = append(socketPaths, xdgRuntime+"/podman/podman.sock")
		socketPaths = append(socketPaths, xdgRuntime+"/docker.sock")
	}

	for _, path := range socketPaths {
		if info, err := os.Stat(path); err == nil {
			// Check if it's a socket and we can access it
			if info.Mode()&os.ModeSocket != 0 {
				// Try to actually access the socket (not just stat it)
				if _, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
					return true
				}
			}
		}
	}

	return false
}

// StartSolaceContainer starts a Solace PubSub+ Standard container for testing
func StartSolaceContainer(ctx context.Context) (*SolaceContainer, error) {
	const (
		adminUser = "admin"
		adminPwd  = "admin"
		sempPort  = "8080/tcp"
	)

	req := testcontainers.ContainerRequest{
		Image:        "solace/solace-pubsub-standard:latest",
		ExposedPorts: []string{sempPort},
		Env: map[string]string{
			"username_admin_globalaccesslevel": "admin",
			"username_admin_password":          adminPwd,
			// Use smaller resource limits suitable for testing
			"system_scaling_maxconnectioncount": "100",
		},
		WaitingFor: wait.ForAll(
			// Wait for the SEMP API to be ready
			wait.ForHTTP("/SEMP/v2/config").
				WithPort("8080").
				WithBasicAuth(adminUser, adminPwd).
				WithStatusCodeMatcher(func(status int) bool {
					return status == http.StatusOK
				}).
				WithStartupTimeout(2 * time.Minute),
		),
		HostConfigModifier: func(hc *container.HostConfig) {
			// Solace needs shared memory
			hc.ShmSize = 1024 * 1024 * 1024 // 1GB
			// Use slirp4netns network mode for rootless podman compatibility
			// This avoids aardvark-dns issues when systemd/dbus is unavailable
			// This setting is ignored by Docker
			if os.Getenv("TESTCONTAINERS_PODMAN_SLIRP4NETNS") != "" {
				hc.NetworkMode = "slirp4netns:port_handler=slirp4netns"
			}
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start Solace container: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped SEMP port: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	return &SolaceContainer{
		Container:  container,
		Host:       fmt.Sprintf("%s:%s", host, mappedPort.Port()),
		AdminUser:  adminUser,
		AdminPwd:   adminPwd,
		SEMPPort:   int(mappedPort.Num()),
		DisableTLS: true,
	}, nil
}

// Terminate stops and removes the container
func (sc *SolaceContainer) Terminate(ctx context.Context) error {
	if sc.Container != nil {
		return sc.Container.Terminate(ctx)
	}
	return nil
}

// GetSEMPURL returns the full SEMP v2 config API URL
func (sc *SolaceContainer) GetSEMPURL() string {
	return fmt.Sprintf("http://%s/SEMP/v2/config", sc.Host)
}

// SkipIfNoDocker skips the test if Docker is not available.
// This allows running tests in environments without Docker.
func SkipIfNoDocker() bool {
	if os.Getenv("SKIP_DOCKER_TESTS") != "" {
		return true
	}
	return !isDockerAvailable()
}
