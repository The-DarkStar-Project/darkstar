package main

import (
	"net/url"
	"strings"
)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func purlVersion(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}
