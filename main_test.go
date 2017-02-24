package main

import (
	"testing"
	. "gopkg.in/check.v1"
	"os"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DnsConfig struct{}

var _ = Suite(&DnsConfig{})

func (s *DnsConfig) TestMain(c *C) {
	var exit int
//	// Test the basic executable works
//	//os.Args = []string{"dns-config", "--help"}
//	//exit = realMain()
//	//c.Check(exit, Equals, 0)
//
	// Test the basic executable works
	os.Args = []string{"dns-config", "get-ips"}
	exit = realMain()
	c.Check(exit, Equals, 0)

	// Test the basic executable works
	os.Args = []string{"dns-config", "get-hostnames"}
	exit = realMain()
	c.Check(exit, Equals, 0)

	// Test the basic executable works
	os.Args = []string{"dns-config", "get", "--use-hostname", "--hostname", "com", "gmail"}
	exit = realMain()
	c.Check(exit, Equals, 0)
}

//func (s *DnsConfig) TestGetIPs(c *C) {
//	c.Fail()
//}

//func (s *DnsConfig) TestGetHostnames(c *C) {
//	c.Fail()
//}
//
//func (s *DnsConfig) TestGet(c *C) {
//	c.Fail()
//}