package auth

import (
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

type GeoIPFilter struct {
	db               *maxminddb.Reader
	allowedCountries map[string]bool
	deniedCountries  map[string]bool
	enabled          bool
}

type geoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewGeoIPFilter(dbPath string, allowedCountries, deniedCountries []string) (*GeoIPFilter, error) {
	filter := &GeoIPFilter{
		allowedCountries: make(map[string]bool),
		deniedCountries:  make(map[string]bool),
	}

	for _, c := range allowedCountries {
		filter.allowedCountries[c] = true
	}
	for _, c := range deniedCountries {
		filter.deniedCountries[c] = true
	}

	if dbPath == "" {
		return filter, nil
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return filter, nil
	}

	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP database %s: %w", dbPath, err)
	}

	filter.db = db
	filter.enabled = true
	return filter, nil
}

func (f *GeoIPFilter) CheckIP(ip net.IP) (bool, string, error) {
	if !f.enabled {
		return true, "", nil
	}

	if len(f.allowedCountries) == 0 && len(f.deniedCountries) == 0 {
		return true, "", nil
	}

	var record geoIPRecord
	err := f.db.Lookup(ip, &record)
	if err != nil {
		return false, "", fmt.Errorf("geoip lookup failed: %w", err)
	}

	countryCode := record.Country.ISOCode
	if countryCode == "" {
		return true, countryCode, nil
	}

	if len(f.deniedCountries) > 0 {
		if f.deniedCountries[countryCode] {
			return false, countryCode, nil
		}
		return true, countryCode, nil
	}

	if len(f.allowedCountries) > 0 {
		if f.allowedCountries[countryCode] {
			return true, countryCode, nil
		}
		return false, countryCode, nil
	}

	return true, countryCode, nil
}

func (f *GeoIPFilter) Close() error {
	if f.db != nil {
		return f.db.Close()
	}
	return nil
}
