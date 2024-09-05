package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
	"gopkg.in/yaml.v2"
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

var conf oauth2.Config
var config Config

func loadConfig() error {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return err
	}
	return nil
}

func saveToken(token *oauth2.Token) error {
	f, err := os.Create(config.TokenFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func loadToken() (*oauth2.Token, error) {
	f, err := os.Open(config.TokenFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var token oauth2.Token
	err = json.NewDecoder(f).Decode(&token)
	return &token, err
}

func authorize() (*oauth2.Token, error) {
	// Kanal für den Autorisierungscode erstellen
	authCodeChan := make(chan string)

	// Starte den Webserver
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, authCodeChan)
	})
	log.Println("Webserver gestartet auf http://localhost:8080/callback")
	go http.ListenAndServe(":8080", nil)

	// Erhalte den Autorisierungs-URL
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Println("Bitte öffne folgenden Link in deinem Browser:", url)
	log.Println("Autorisierungs-URL generiert:", url)

	// Warte auf den Autorisierungscode
	authCode := <-authCodeChan
	log.Println("Autorisierungscode erhalten:", authCode)

	// Tausche den Autorisierungscode gegen ein Token aus
	token, err := conf.Exchange(context.Background(), authCode)
	if err != nil {
		return nil, err
	}

	if err := saveToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

func getToken() (*oauth2.Token, error) {
	// Versuche, den gespeicherten Token zu laden
	token, err := loadToken()
	if err != nil || !token.Valid() {
		log.Println("Kein gültiger Token gefunden, starte Autorisierung")
		token, err = authorize()
		if err != nil {
			return nil, fmt.Errorf("Fehler bei der Autorisierung: %v", err)
		}
	} else {
		log.Println("Gültiger Token gefunden")
	}
	return token, nil
}

func uploadFile(client *http.Client, localFilePath, oneDriveFilePath string) error {
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("Fehler beim Öffnen der Datei: %v", err)
	}
	defer file.Close()
	log.Println("Datei erfolgreich geöffnet:", localFilePath)

	req, err := http.NewRequest("PUT", "https://graph.microsoft.com/v1.0/me/drive/root:/"+oneDriveFilePath+":/content", file)
	if err != nil {
		return fmt.Errorf("Fehler beim Erstellen der Anfrage: %v", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	log.Println("HTTP-Anfrage erstellt für:", oneDriveFilePath)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Fehler beim Hochladen der Datei: %v", err)
	}
	defer resp.Body.Close()
	log.Println("Datei erfolgreich hochgeladen:", oneDriveFilePath)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Fehler beim Lesen der Antwort: %v", err)
	}

	var response map[string]interface{}
	json.Unmarshal(body, &response)
	fmt.Println("Datei erfolgreich hochgeladen:", response)
	log.Println("Datei erfolgreich hochgeladen:", response)
	return nil
}

func uploadFolder(client *http.Client, localFolderPath, oneDriveFolderPath string) error {
	err := filepath.Walk(localFolderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relativePath, err := filepath.Rel(localFolderPath, path)
			if err != nil {
				return err
			}
			oneDriveFilePath := filepath.Join(oneDriveFolderPath, relativePath)
			if err := uploadFile(client, path, oneDriveFilePath); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

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
	if err := loadConfig(); err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		log.Println("Fehler beim Laden der Konfiguration:", err)
		return
	}

	// OAuth2-Konfiguration initialisieren
	conf = oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       []string{config.Scopes},
		Endpoint:     microsoft.AzureADEndpoint(config.TenantID),
		RedirectURL:  config.RedirectURL,
	}

	// Erhalte das Token
	token, err := getToken()
	if err != nil {
		fmt.Println(err)
		log.Println(err)
		return
	}

	client := conf.Client(context.Background(), token)

	// Lade den Ordner hoch
	if err := uploadFolder(client, config.LocalFolder, config.OneDrivePath); err != nil {
		fmt.Println(err)
		log.Println(err)
		return
	}

	fmt.Println("Drücken Sie Enter, um das Programm zu beenden.")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	log.Println("Programm beendet")
}

func handleCallback(w http.ResponseWriter, r *http.Request, authCodeChan chan string) {
	// Extrahiere den Autorisierungscode aus der Anfrage
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		http.Error(w, "Kein Autorisierungscode erhalten", http.StatusBadRequest)
		log.Println("Kein Autorisierungscode erhalten")
		return
	}
	log.Println("Autorisierungscode erhalten:", authCode)

	// Sende den Autorisierungscode über den Kanal
	authCodeChan <- authCode

	// Bestätige den Empfang des Autorisierungscodes
	fmt.Fprintf(w, "Autorisierungscode erhalten. Sie können dieses Fenster jetzt schließen.")
}

func encrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
