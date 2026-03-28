package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amenyxia/Sarracenia/pkg/templating"
)

// newTestConfigManager builds a minimal ConfigManager with the given trusted proxies.
func newTestConfigManager(trustedProxies []string) *ConfigManager {
	cfg := &Config{
		Server:    DefaultServerConfig(),
		Templates: templating.DefaultConfig(),
		Threat:    DefaultThreatConfig(),
	}
	cfg.Server.TrustedProxies = trustedProxies

	cm := &ConfigManager{
		config: cfg,
		logger: slog.Default(),
	}
	cm.refreshCache()
	return cm
}

func TestGetClientIP(t *testing.T) {
	cases := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		want           string
	}{
		{
			name:       "no trusted proxies returns remote addr",
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "untrusted peer ignores X-Real-IP",
			remoteAddr: "1.2.3.4:1234",
			headers:    map[string]string{"X-Real-IP": "9.9.9.9"},
			want:       "1.2.3.4",
		},
		{
			name:       "untrusted peer ignores X-Forwarded-For",
			remoteAddr: "1.2.3.4:1234",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9"},
			want:       "1.2.3.4",
		},
		{
			name:           "trusted proxy with X-Real-IP returns X-Real-IP",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:1234",
			headers:        map[string]string{"X-Real-IP": "5.6.7.8"},
			want:           "5.6.7.8",
		},
		{
			name:           "trusted proxy with CF-Connecting-IP returns CF header",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:1234",
			headers:        map[string]string{"CF-Connecting-IP": "5.6.7.8"},
			want:           "5.6.7.8",
		},
		{
			name:           "CF-Connecting-IP takes precedence over X-Real-IP",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:1234",
			headers: map[string]string{
				"CF-Connecting-IP": "5.6.7.8",
				"X-Real-IP":        "9.9.9.9",
			},
			want: "5.6.7.8",
		},
		{
			name:           "X-Real-IP takes precedence over X-Forwarded-For",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:1234",
			headers: map[string]string{
				"X-Real-IP":       "5.6.7.8",
				"X-Forwarded-For": "9.9.9.9",
			},
			want: "5.6.7.8",
		},
		{
			name:           "trusted proxy with X-Forwarded-For returns first untrusted IP",
			trustedProxies: []string{"10.0.0.1", "10.0.0.2"},
			remoteAddr:     "10.0.0.1:1234",
			headers:        map[string]string{"X-Forwarded-For": "5.6.7.8, 10.0.0.2"},
			want:           "5.6.7.8",
		},
		{
			name:           "trusted CIDR proxy with X-Real-IP returns X-Real-IP",
			trustedProxies: []string{"10.0.0.0/24"},
			remoteAddr:     "10.0.0.5:1234",
			headers:        map[string]string{"X-Real-IP": "5.6.7.8"},
			want:           "5.6.7.8",
		},
		{
			name:           "no headers from trusted proxy returns proxy addr",
			trustedProxies: []string{"10.0.0.1"},
			remoteAddr:     "10.0.0.1:1234",
			want:           "10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm := newTestConfigManager(tc.trustedProxies)
			s := &Server{cm: cm}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			got := s.getClientIP(req)
			if got != tc.want {
				t.Errorf("getClientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
