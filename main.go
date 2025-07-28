package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

type AuthResponse struct {
	XMLName  xml.Name `xml:"Auth"`
	CSRFCode string   `xml:"CSRF_RAND_CODE"`
	RSAKey   string   `xml:"RSA_ENCRYPT_KEY"`
	RSAExp   string   `xml:"RSA_ENCRYPT_EXP"`
	TWFID    string   `xml:"TwfID"`
	Result   string   `xml:"Result"`
	Message  string   `xml:"Message"`
}

func zjuWebVPNLogin(username, password string) (string, []*http.Cookie, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", nil, err
	}
	client := &http.Client{Jar: jar}

	authReq, _ := http.NewRequest("GET", "https://webvpn.zju.edu.cn/por/login_auth.csp?apiversion=1", nil)
	resp, err := client.Do(authReq)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	var auth AuthResponse
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	if err := xml.Unmarshal(buf.Bytes(), &auth); err != nil {
		return "", nil, fmt.Errorf("xml decode error: %v", err)
	}

	modulus := new(big.Int)
	modulus.SetString(auth.RSAKey, 16)
	publicKey := &rsa.PublicKey{N: modulus, E: 65537}

	plain := fmt.Sprintf("%s_%s", password, auth.CSRFCode)
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(plain))
	if err != nil {
		return "", nil, err
	}
	encryptedHex := hex.EncodeToString(encrypted)

	form := url.Values{}
	form.Add("mitm_result", "")
	form.Add("svpn_req_randcode", auth.CSRFCode)
	form.Add("svpn_name", username)
	form.Add("svpn_password", encryptedHex)
	form.Add("svpn_rand_code", "")

	loginReq, err := http.NewRequest("POST", "https://webvpn.zju.edu.cn/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1", strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, err
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Referer", "https://webvpn.zju.edu.cn/por/login.csp")
	loginReq.Header.Set("User-Agent", "Mozilla/5.0")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		return "", nil, err
	}
	defer loginResp.Body.Close()

	buf.Reset()
	io.Copy(buf, loginResp.Body)

	var loginResult AuthResponse
	if err := xml.Unmarshal(buf.Bytes(), &loginResult); err != nil {
		return "", nil, err
	}

	if loginResult.Result != "1" {
		return "", nil, fmt.Errorf("login failed: %s", loginResult.Message)
	}

	for _, c := range loginResp.Cookies() {
		if c.Name == "TWFID" {
			return c.Value, loginResp.Cookies(), nil
		}
	}
	return "", nil, errors.New("TWFID not found")
}

func handleConnection(conn net.Conn, wsURL string, cookie string) {
	defer conn.Close()

	header := http.Header{}
	header.Set("Cookie", "TWFID="+cookie)

	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		log.Printf("[ERROR] WebSocket连接失败: %v", err)
		return
	}
	defer wsConn.Close()

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			_, err = conn.Write(msg)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	<-errCh
}

func main() {
	var containerID string
	var username string
	var password string
	var listenHost string
	var listenPort int

	flag.StringVar(&containerID, "container-id", "", "ZJUCTF container ID")
	flag.StringVar(&username, "username", "", "ZJU WebVPN username")
	flag.StringVar(&password, "password", "", "ZJU WebVPN password")
	flag.StringVar(&listenHost, "listen-host", "127.0.0.1", "Listen host")
	flag.IntVar(&listenPort, "listen-port", 20123, "Listen port")
	flag.Parse()

	if containerID == "" || username == "" || password == "" {
		flag.Usage()
		os.Exit(1)
	}

	twfid, _, err := zjuWebVPNLogin(username, password)
	if err != nil {
		log.Fatalf("[ERROR] 登录失败: %v", err)
	}

	wsURL := fmt.Sprintf("ws://ctf-zjusec-com-s.webvpn.zju.edu.cn:8001/api/proxy/%s", containerID)

	addr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	log.Printf("[TCP] 正在监听 %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		log.Printf("[TCP] 接受连接: %s", conn.RemoteAddr())
		go handleConnection(conn, wsURL, twfid)
	}
}
