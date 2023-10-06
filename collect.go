package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/time/rate"
)

func main() {
	cveYears := make(map[int]io.WriteCloser)

	type NVDResponse struct {
		ResultsPerPage  int `json:"resultsPerPage"`
		TotalResults    int `json:"totalResults"`
		StartIndex      int `json:"startIndex"`
		Vulnerabilities []struct {
			CVE map[string]interface{} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	limiter := rate.NewLimiter(40/30, 2)

	startIndex := 0
	totalResults := 1_000_000_000 // Larger than any possible number of CVEs
	for startIndex < totalResults {
		limiter.Wait(context.Background())
		log.Println("Downloading index ", startIndex)
		// Get the next 1000 CVEs
		url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=%d", startIndex)
		req, err := http.NewRequestWithContext(context.TODO(), "GET", url, nil)
		req.Header.Set("apiKey", os.Getenv("NVD_API_KEY"))
		if err != nil {
			log.Fatalf("failed to create request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)

		if err != nil {
			log.Fatalf("failed to get response: %w", err)
		}

		var decodedResponse NVDResponse

		err = json.NewDecoder(resp.Body).Decode(&decodedResponse)
		if err != nil {
			log.Fatalf("failed to decode response: %w", err)
		}
		totalResults = decodedResponse.TotalResults
		startIndex = decodedResponse.StartIndex + decodedResponse.ResultsPerPage

		for _, cve := range decodedResponse.Vulnerabilities {
			id := cve.CVE["id"]
			year, err := strconv.Atoi(id.(string)[4:8])
			if err != nil {
				log.Fatalf("failed to parse year: %w", err)
			}
			if _, ok := cveYears[year]; !ok {
				f, err := os.Create(fmt.Sprintf("nvd_cve/%d.jsonl.zst", year))
				if err != nil {
					log.Fatalf("failed to create file: %w", err)
				}
				defer f.Close()
				zst, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
				if err != nil {
					log.Fatalf("failed to create zstd writer: %w", err)
				}
				defer zst.Close()

				cveYears[year] = zst
			}
			err = json.NewEncoder(cveYears[year]).Encode(cve.CVE)
			if err != nil {
				log.Fatalf("failed to encode cve: %w", err)
			}
		}

	}

}
