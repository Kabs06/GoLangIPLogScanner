package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

// Setting up IPv4 Pattern matching expression

var ip4Expr = regexp.MustCompile(`((\d{1,3})\.){3}\d{1,3}`)

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

	defer file.Close()
	scanner := bufio.NewScanner(file)

	foundAdresses := make(map[string]int)

	for scanner.Scan() {

		// Storing the current log line we are going to analyse

		s := scanner.Text()

		match := ip4Expr.FindString(s)

		if match != "" {

			// Increments the number of occurence associated to the IP Adress :

			foundAdresses[match]++

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

func BruteforceChecker(m map[string]int) {
	for k, v := range m {
		if v > 10 {
			fmt.Printf("IP Adress : %s has been detected as a potential bruteforce attack, with %d attempts\n", k, v)
		}
	}
}
