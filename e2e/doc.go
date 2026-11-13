// Package e2e runs the real sensor image in Docker, with real packet capture
// and syslog, against a fake NxtFireGuard backend. The tests carry the build
// tag e2e and need Docker:
//
//	go test -tags e2e -count=1 -v -timeout 20m ./e2e/
//
// See "Testing" in the README.
package e2e
