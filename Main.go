package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"

	"dexpro-solutions-gmbh/squeeze-export-to-onedrive/pkg/onedrive"
)

type Config struct {
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	TenantID     string `yaml:"tenantID"`
	Scopes       string `yaml:"scopes"`
	RedirectURL  string `yaml:"redirectURL"`
	TokenFile    string `yaml:"tokenFile"`
	LocalFolder  string `yaml:"localFolder"`
	OneDrivePath string `yaml:"oneDrivePath"`
}

func LoadConfig() error {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &configData)
	if err != nil {
		return err
	}
	return nil
}

var configData Config

func main() {
	// Log-Datei initialisieren
	logFile, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Fehler beim Öffnen der Log-Datei:", err)
		return
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Konfiguration laden
	if err := LoadConfig(); err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		log.Println("Fehler beim Laden der Konfiguration:", err)
		return
	}
	// Beispiel für die Initialisierung des OneDriveClients
	client := onedrive.NewClient(
		configData.RedirectURL,
		configData.ClientID,
		configData.ClientSecret,
		configData.TenantID,
		configData.Scopes,
		configData.TokenFile,
	)

	// Lade den Ordner hoch
	if err := client.UploadFolder(configData.LocalFolder, configData.OneDrivePath, nil); err != nil {
		fmt.Println(err)
		log.Println(err)
		return
	}

	fmt.Println("Drücken Sie Enter, um das Programm zu beenden.")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	log.Println("Programm beendet")
}
