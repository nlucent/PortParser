package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

func main() {
	const hammerCmd = "hammer host list"
	const portCmd = "netstat --tcp --udp --listening --program --numeric-ports"

	var help bool
	satServer := flag.String("sat", "", "Satellite Server to gather hammer host data from")
	serverCmd := flag.String("command", portCmd, "Command to be run on remote servers")
	sshPort := flag.String("port", "22", "SSH Port")
	userName := flag.String("username", "", "Username to use for SSH connections")
	passWord := flag.String("password", "", "Password for SSH connections")
	outFile := flag.String("outfile", "output.csv", "Output file for CSV data")
	flag.BoolVar(&help, "help", false, "Help Text")
	flag.Parse()
	if help == true {
		printHelp()
		return
	}

	servers := make(map[string]string)

	fmt.Println("Connecting to " + *satServer)
	hammer_hosts := sshCommand(*userName, *passWord, *satServer, *sshPort, hammerCmd)
	parseHammer(hammer_hosts, servers)

	for k, v := range servers {
		if !strings.Contains(k, "template") {
			fmt.Println("Connecting to ", k)
			server_ports := sshCommand(*userName, *passWord, v, *sshPort, *serverCmd)
			parseNetstat(k, server_ports, *outFile)
		}
	}

}

func printHelp() {
	fmt.Println("-sat", "Satellite Server to gather hammer host data from")
	fmt.Println("-command", "Command to be run on remote servers")
	fmt.Println("-port", "SSH Port")
	fmt.Println("-username", "Username to use for SSH connections")
	fmt.Println("-password", "Password for SSH connections")
	fmt.Println("-outfile", "Output file for CSV data")
	fmt.Println("-help", "Help Text")
}

func parseHammer(vals []string, servers map[string]string) {
	var validIP = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`)

	for _, line := range vals {
		line_data := strings.Split(line, "|")
		if len(line_data) > 5 && validIP.MatchString(strings.TrimSpace(line_data[4])) {
			servers[strings.TrimSpace(line_data[1])] = strings.TrimSpace(line_data[4])
		}
	}
}

func parseNetstat(server string, ports []string, outfile string) {

	var file *os.File
	var writer *csv.Writer
	// Append if file exists
	if _, err := os.Stat(outfile); os.IsNotExist(err) {
		file, err = os.Create(outfile)
		if err != nil {
			log.Println("Error opening" + outfile)
			return
		}
		writer = csv.NewWriter(file)
		writer.Write([]string{"Short Name", "Process", "Port", "Protocol"})

	} else {
		file, err = os.Open(outfile)
		writer = csv.NewWriter(file)
	}
	defer file.Close()
	defer writer.Flush()

	for _, line := range ports {
		short_name := strings.Replace(strings.Split(server, ".")[0], "nightly", "", -1)

		if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {

			vals := strings.Fields(line)
			if len(vals) > 5 {
				proto, port, proc := vals[0], vals[3], vals[5]
				_, port, _ = net.SplitHostPort(port)
				if strings.Index(proc, "/") > 0 {
					p := strings.Split(proc, "/")
					proc = p[1]
				} else {
					proc = "Unknown"
				}
				writer.Write([]string{short_name, proc, port, proto})
			}
		}
	}
}

func sshCommand(username string, password string, host string, port string, cmd string) []string {
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", host+":"+port, sshConfig)
	if err != nil {
		log.Panic(err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		log.Panicf("Error establishing session: %s", err)
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(cmd); err != nil {
		log.Fatal("Failed to run:" + err.Error())
	}

	output := strings.Split(b.String(), "\n")
	return output
}
