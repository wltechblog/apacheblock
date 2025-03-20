package main

type CaddyLogEntry struct {
	Request struct {
		ClientIP string `json:"client_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
	} `json:"request"`
	Status int64 `json:"status"`
}
