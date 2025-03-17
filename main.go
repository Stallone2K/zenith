package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"zenith/internal"
)

const hashFile = "hashes.json"

type FileHashes struct {
	Files map[string]string `json:"files"`
}

func loadHashes() (*FileHashes, error) {
	file, err := os.Open(hashFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes FileHashes
	if err := json.NewDecoder(file).Decode(&hashes); err != nil {
		return nil, err
	}
	return &hashes, nil
}

func saveHashes(hashes *FileHashes) error {
	file, err := os.Create(hashFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(hashes)
}

func verifyIntegrity() {
	hashes, err := loadHashes()
	if err != nil {
		log.Fatalf("Error Loading Hashes: %v", err)
	}

	for filePath, storedHash := range hashes.Files {
		currentHash, err := internal.ComputeSHA256(filePath)
		if err != nil {
			fmt.Printf("⚠️  Could Not Hash %s: %v\n", filePath, err)
			continue
		}

		if currentHash == storedHash {
			fmt.Printf("✅ %s: No Changes Detected.\n", filePath)
		} else {
			fmt.Printf("❌ %s: File Has Been Modified!\n", filePath)
			fmt.Print("Would You Like To Update The Hash? (Y/N): ")

			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			if input == "y" {
				hashes.Files[filePath] = currentHash
				saveHashes(hashes)
				fmt.Println("✅ Hash Updated Successfully!")
			}
		}
	}
}

func updateHash(filePath string) {
	hashes, err := loadHashes()
	if err != nil {
		log.Fatalf("Error Loading Hashes: %v", err)
	}

	newHash, err := internal.ComputeSHA256(filePath)
	if err != nil {
		log.Fatalf("Failed To Hash File: %v", err)
	}

	hashes.Files[filePath] = newHash
	if err := saveHashes(hashes); err != nil {
		log.Fatalf("Error Saving Updated Hashes: %v", err)
	}

	fmt.Println("✅ Hash Updated Successfully!")
}

func scanForMalware() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter File Path To Scan: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	detected, err := internal.ScanFile(filePath) // ✅ Pass only `filePath`
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
	} else if detected {
		fmt.Println("🚨 Malware Found!")
	} else {
		fmt.Println("✅ File is Clean.")
	}
}

func main() {
	fmt.Println(`
__ ___    ___    
 /|__ |\ ||||__| 
/_|___| \||||  | 
                 `)
	fmt.Println("Choose An Option: ⬇️")
	fmt.Println("1. Verify File Integrity✅")
	fmt.Println("2. Update File Hash #️⃣")
	fmt.Println("3. Scan for Malware 🐞")
	fmt.Print("Enter Option: ")

	var choice int
	fmt.Scan(&choice)

	switch choice {
	case 1:
		verifyIntegrity()
	case 2:
		fmt.Print("Enter File Path To Update Hash: ")
		var filePath string
		fmt.Scan(&filePath)
		updateHash(filePath)
	case 3:
		scanForMalware()
	default:
		fmt.Println("Invalid Option.")
	}
}
