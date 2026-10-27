package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
)

// Setting up IPv4 and IPv6 Pattern matching expression

var ipExpr = regexp.MustCompile(`((\d{1,3}\.){3}\d{1,3})|(([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))`)

func main() {

	var filePath string
	var finished bool
	var err error
	var file *os.File

	// Input section :

	for !finished {

		// User input section :

		fmt.Print("Please, enter a valid .log file destination to read :")
		fmt.Scan(&filePath)

		file, err = os.Open(filePath)

		if err == nil {

			finished = true

		}

	}

	finished = false

	var str string
	var subnet *net.IPNet

	// Waiting for user input for an subnet IP Adress :
	for !finished {
		fmt.Print("Please, enter the subnet IP Adress (CIDR notation) :")
		fmt.Scan(&str)
		_, subnet, err = net.ParseCIDR(str)
		if err == nil {
			finished = true
		}

	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	foundAdresses := make(map[string]*IPAddressReport)

	for scanner.Scan() {

		// Storing the current log line we are going to analyse

		s := scanner.Text()

		match := ipExpr.FindString(s)

		if match != "" {

			parsedIP := net.ParseIP(match)
			fmt.Print(parsedIP, "\n")
			if parsedIP != nil && !subnet.Contains(parsedIP) {

				// Si l'IP n'est pas encore dans la map, on crée son rapport
				report, exists := foundAdresses[match]
				if !exists {
					report = &IPAddressReport{IPAddress: match}
					foundAdresses[match] = report
				}

				report.Attempts++

			}

		}
	}

	fmt.Print("all IP adresses have been extracted, select the next action : \n 1 - Check for bruteforce / login spamming")
	var optInp int
	fmt.Scan(&optInp)
	switch optInp {
	case 1:
		BruteforceChecker(foundAdresses)
	}

}

// Advanced struct who provides report data about the IP Adress :
type IPAddressReport struct {
	IPAddress  string
	Attempts   int
	Successful bool
}

// Function that will determine if an attacker tries to bruteforce acces or not :
func BruteforceChecker(m map[string]*IPAddressReport) {

	for _, v := range m {
		if v.Attempts > 10 {
			fmt.Printf("IP Address : %s has been detected as a potential bruteforce attack, with %d attempts\n", v.IPAddress, v.Attempts)
		}

	}

}
