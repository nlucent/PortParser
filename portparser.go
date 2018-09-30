package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	const hammerCmd = "hammer host list"
	const portCmd = "netstat --tcp --udp --listening --program --numeric-ports"

	var output string

	satServer := flag.String("sat", "", "Satellite Server to gather hammer host data from")
	serverCmd := flag.String("command", portCmd, "Command to be run on remote servers")
	sshPort := flag.String("port", "22", "SSH Port")
	userName := flag.String("username", "", "Username to use for SSH connections")
	passWord := flag.String("password", "", "Password for SSH connections")
	outFile := flag.String("outfile", "output.csv", "Output file for CSV data")
	silentFlag := flag.Bool("silent", false, "Prevent all extraneous output (for piping/automation)")
	quietFlag := flag.Bool("quiet", false, "Pipe informational messages to Stderr")
	timeIt := flag.Bool("timeit", false, "Time each process")
	flag.Parse()

	if *quietFlag {
		output = "quiet"
	} else if *silentFlag {
		output = "silent"
	} else {
		output = "standard"
	}

	servers := make(map[string]string)
	ch := make(chan []string)

	logOutput("\nConnecting to "+*satServer+"...", output)
	go sshCommand(*userName, *passWord, *satServer, *sshPort, hammerCmd, ch)
	hammer_hosts := <-ch
	parseHammer(hammer_hosts, servers)
	logOutput(" Found "+strconv.Itoa(len(servers))+" servers.\n\n", output)
	for k, v := range servers {
		if !strings.Contains(k, "template") {
			logOutput("Connecting to "+k, output)
			start := time.Now()
			go sshCommand(*userName, *passWord, v, *sshPort, *serverCmd, ch)
			server_ports := <-ch
			if *serverCmd == portCmd {
				logOutput(" ("+strconv.Itoa(len(server_ports))+")", output)
				parseNetstat(k, v, server_ports, *outFile)
			} else {
				logOutput(" ("+strconv.Itoa(len(server_ports))+" results)", output)
				if !*timeIt {
					logOutput("\n", output)
				} else {
					logOutput(", "+time.Since(start).String()+"\n", output)
				}
				fmt.Println(server_ports)
			}
		}

	}
}

func logOutput(msg string, outputType string) {
	if outputType == "silent" {
		// dont print informational messages
		fmt.Fprint(ioutil.Discard, msg)
		return
	} else if outputType == "quiet" {
		// print to stderr
		fmt.Fprint(os.Stderr, msg)
	} else {
		// print to stdout
		fmt.Print(msg)
	}
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

func parseNetstat(server string, ipaddr string, ports []string, outfile string) {
	set := make(map[string]bool)
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
				data := make([]string, 8)
				ch := make(chan string)
				data[0], data[1], data[2], data[3], data[4], data[5], data[6] = "", short_name, "", proc, short_name, port, proto
				newkey := short_name + proc + port + proto
				if _, ok := set[newkey]; !ok {
					set[newkey] = true
					go testPort(ipaddr, port, proto, ch)
					data[7] = <-ch
					err := writeCSV(data, outfile)
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
	}
}

func testPort(host string, port string, proto string, ch chan string) {
	conn, err := net.Dial(proto, host+":"+port)
	if err != nil {
		ch <- "Closed"
	}
	ch <- "Open"
	conn.Close()
}

func writeCSV(val []string, outfile string) error {
	var file *os.File
	var writer *csv.Writer
	if _, err := os.Stat(outfile); os.IsNotExist(err) {
		file, err = os.Create(outfile)
		if err != nil {
			log.Println("Error opening" + outfile)
			return err
		}
		writer = csv.NewWriter(file)
		writer.Write([]string{"Provider Team", "Provider Application", "User Product Team", "User Application", "Device/Service", "Port", "Protocol", "FW_Open"})

	} else {
		file, err = os.OpenFile(outfile, os.O_APPEND|os.O_WRONLY, 0666)
		writer = csv.NewWriter(file)
	}
	defer file.Close()
	writer.Write(val)
	writer.Flush()

	return nil
}

func sshCommand(username string, password string, host string, port string, cmd string, ch chan []string) {
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", host+":"+port, sshConfig)
	if err != nil {
		fmt.Println(err)
		ch <- []string{""}
		return
	}
	defer conn.Close()

	session, err := conn.NewSession()
	defer session.Close()
	if err != nil {
		fmt.Println(err)
		ch <- []string{""}
		return
	}

	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(cmd); err != nil {
		fmt.Println(err)
		ch <- []string{""}
		return
	}

	ch <- strings.Split(b.String(), "\n")
}
