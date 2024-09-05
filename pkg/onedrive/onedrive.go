package onedrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type OneDriveClient struct {
	RedirectUrl   string
	Conf          *oauth2.Config
	Token         *oauth2.Token
	Client        *http.Client
	TokenFilePath string
}

func NewClient(redirectUrl, clientID, clientSecret, tenantID, scopes, tokenFilePath string) *OneDriveClient {
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUrl,
		Scopes:       []string{scopes},
		Endpoint:     microsoft.AzureADEndpoint(tenantID),
	}

	return &OneDriveClient{
		RedirectUrl:   redirectUrl,
		Conf:          conf,
		Token:         nil,
		Client:        nil,
		TokenFilePath: tokenFilePath,
	}
}

func (c *OneDriveClient) Authorize() (*oauth2.Token, error) {
	// Kanal für den Autorisierungscode erstellen
	authCodeChan := make(chan string)

	// URL parsen
	parsedRedirectUrl, err := url.Parse(c.RedirectUrl)
	if err != nil {
		fmt.Println("Fehler beim Parsen der URL:", err)
		return nil, err
	}

	// Port extrahieren
	redirectUrlPort := parsedRedirectUrl.Port()
	if redirectUrlPort == "" {
		redirectUrlPort = "80"
	}

	// Pfad extrahieren
	redirectUrlPath := parsedRedirectUrl.Path

	// Starte den Webserver
	http.HandleFunc(redirectUrlPath, func(w http.ResponseWriter, r *http.Request) {
		c.HandleCallback(w, r, authCodeChan)
	})
	log.Println("Webserver gestartet auf " + c.RedirectUrl)
	go http.ListenAndServe(":"+redirectUrlPort, nil)

	// Erhalte den Autorisierungs-URL
	url := c.Conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Println("Bitte öffne folgenden Link in deinem Browser:", url)
	log.Println("Autorisierungs-URL generiert:", url)

	// Warte auf den Autorisierungscode
	authCode := <-authCodeChan
	log.Println("Autorisierungscode erhalten:", authCode)

	// Tausche den Autorisierungscode gegen ein Token aus
	token, err := c.Conf.Exchange(context.Background(), authCode)
	if err != nil {
		return nil, err
	}

	if err := c.SaveToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

func (c *OneDriveClient) LoadToken() (*oauth2.Token, error) {
	f, err := os.Open(c.TokenFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var token oauth2.Token
	err = json.NewDecoder(f).Decode(&token)
	return &token, err
}

func (c *OneDriveClient) SaveToken(token *oauth2.Token) error {
	f, err := os.Create(c.TokenFilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func (c *OneDriveClient) GetToken() (*oauth2.Token, error) {
	// Versuche, den gespeicherten Token zu laden
	token, err := c.LoadToken()
	if err != nil || !token.Valid() {
		log.Println("Kein gültiger Token gefunden, starte Autorisierung")
		token, err = c.Authorize()
		if err != nil {
			return nil, fmt.Errorf("Fehler bei der Autorisierung: %v", err)
		}
	} else {
		log.Println("Gültiger Token gefunden")
	}
	return token, nil
}

func (c *OneDriveClient) UploadFile(localFilePath, oneDriveFilePath string, client *http.Client) error {
	// Überprüfen, ob der übergebene Client nil ist
	if client == nil {
		var err error
		client, err = c.GetAuthenticatedClient()
		if err != nil {
			return fmt.Errorf("Fehler bei der Authentifizierung: %v", err)
		}
	}

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

func (c *OneDriveClient) UploadFolder(localFolderPath, oneDriveFolderPath string, client *http.Client) error {
	// Überprüfen, ob der übergebene Client nil ist
	if client == nil {
		var err error
		client, err = c.GetAuthenticatedClient()
		if err != nil {
			return fmt.Errorf("Fehler bei der Authentifizierung: %v", err)
		}
	}

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
			if err := c.UploadFile(path, oneDriveFilePath, client); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (c *OneDriveClient) HandleCallback(w http.ResponseWriter, r *http.Request, authCodeChan chan string) {
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

// Überprüft, ob der aktuelle Token gültig ist und einen neuen Client zurückgibt
func (c *OneDriveClient) GetAuthenticatedClient() (*http.Client, error) {
	// Überprüfen, ob der aktuelle Token gültig ist
	if c.Token == nil || !c.Token.Valid() {
		log.Println("Kein gültiger Token vorhanden, starte Autorisierung")
		token, err := c.GetToken()
		if err != nil {
			return nil, fmt.Errorf("Fehler bei der Autorisierung: %v", err)
		}
		c.Token = token
	} else {
		log.Println("Gültiger Token vorhanden")
	}

	// Erstelle und gebe einen neuen HTTP-Client zurück
	client := c.Conf.Client(context.Background(), c.Token)
	return client, nil
}
