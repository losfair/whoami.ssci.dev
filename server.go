package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	server := &Server{
		sessionInfo: make(map[string]sessionInfo),
	}
	server.sshConfig = &ssh.ServerConfig{
		KeyboardInteractiveCallback: server.KeyboardInteractiveCallback,
		PublicKeyCallback:           server.PublicKeyCallback,
	}

	privKey, err := generateSSHPrivateKey()
	fatalIfErr(err)
	server.sshConfig.AddHostKey(privKey)
	log.Println("Loaded keys...")

	listener, err := net.Listen("tcp", ":2222")
	fatalIfErr(err)
	log.Println("Listening...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept failed:", err)
			continue
		}

		go server.Handle(conn)
	}
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var agentMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

           You have SSH agent forwarding turned (universally?) on.
         That is a VERY BAD idea. For example, right now this server
          has access to your agent and can use your keys however it
                    likes as long as you are connected.

               ANY SERVER YOU LOG IN TO AND ANYONE WITH ROOT ON
                   THOSE SERVERS CAN LOGIN AS YOU ANYWHERE.

                       Read more:  http://git.io/vO2A6
`, "\n", "\n\r", -1))

var x11Msg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

               You have X11 forwarding turned (universally?) on.
          That is a VERY BAD idea. For example, right now this server
              has access to your desktop, windows, and keystrokes
                         as long as you are connected.

                ANY SERVER YOU LOG IN TO AND ANYONE WITH ROOT ON
         THOSE SERVERS CAN SNIFF YOUR KEYSTROKES AND ACCESS YOUR WINDOWS.

     Read more:  http://www.hackinglinuxexposed.com/articles/20040705.html
`, "\n", "\n\r", -1))

var roamingMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

    You have roaming turned on. If you are using OpenSSH, that most likely
       means you are vulnerable to the CVE-2016-0777 information leak.

   THIS MEANS THAT ANY SERVER YOU CONNECT TO MIGHT OBTAIN YOUR PRIVATE KEYS.

     Add "UseRoaming no" to the "Host *" section of your ~/.ssh/config or
           /etc/ssh/ssh_config file, rotate keys and update ASAP.

Read more:  https://www.qualys.com/2016/01/14/cve-2016-0777-cve-2016-0778/openssh-cve-2016-0777-cve-2016-0778.txt
`, "\n", "\n\r", -1))

type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	sshConfig *ssh.ServerConfig

	mu          sync.RWMutex
	sessionInfo map[string]sessionInfo
}

func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	si := s.sessionInfo[string(conn.SessionID())]
	si.User = conn.User()
	si.Keys = append(si.Keys, key)
	s.sessionInfo[string(conn.SessionID())] = si
	s.mu.Unlock()

	// Never accept a key, or we might not see the next.
	return nil, errors.New("")
}

func (s *Server) KeyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys.
	return nil, nil
}

type logEntry struct {
	Timestamp     string
	Error         string `json:",omitempty"`
	ClientVersion string `json:",omitempty"`
}

func (s *Server) Handle(nConn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		// Port scan, health check, or dictionary attack.
		return
	}
	le := &logEntry{Timestamp: time.Now().Format(time.RFC3339)}
	defer json.NewEncoder(os.Stdout).Encode(le)
	var agentFwd, x11, roaming bool
	defer func() {
		s.mu.Lock()
		delete(s.sessionInfo, string(conn.SessionID()))
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()
	go func(in <-chan *ssh.Request) {
		for req := range in {
			if req.Type == "roaming@appgate.com" {
				roaming = true
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(reqs)

	s.mu.RLock()
	si := s.sessionInfo[string(conn.SessionID())]
	s.mu.RUnlock()

	le.ClientVersion = string(conn.ClientVersion())

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			le.Error = "Channel accept failed: " + err.Error()
			return
		}
		defer channel.Close()

		reqLock := &sync.Mutex{}
		reqLock.Lock()
		timeout := time.AfterFunc(30*time.Second, func() { reqLock.Unlock() })

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				case "shell":
					fallthrough
				case "pty-req":
					ok = true

					// "auth-agent-req@openssh.com" and "x11-req" always arrive
					// before the "pty-req", so we can go ahead now
					if timeout.Stop() {
						reqLock.Unlock()
					}

				case "auth-agent-req@openssh.com":
					agentFwd = true
				case "x11-req":
					x11 = true
				}

				if req.WantReply {
					req.Reply(ok, nil)
				}
			}
		}(requests)

		reqLock.Lock()
		if agentFwd {
			channel.Write(agentMsg)
		}
		if x11 {
			channel.Write(x11Msg)
		}
		if roaming {
			channel.Write(roamingMsg)
		}

		var clientKeys []string
		for _, key := range si.Keys {
			clientKeys = append(clientKeys, string(ssh.MarshalAuthorizedKey(key)))
		}

		channel.Write([]byte(strings.Replace(
			fmt.Sprintf("Hello %s! This is a demo application for SSCI (https://github.com/losfair/ssci).\n\nIt will echo the SSH public keys that your client uses to authenticate, but nobody except you can't see them - not even us.\n\nYour client sent the following public keys:\n\n", si.User)+strings.Join(clientKeys, "")+"\n",
			"\n", "\n\r", -1)))

		time.Sleep(3 * time.Second)
		return
	}
}

func generateSSHPrivateKey() (sshPriv ssh.Signer, err error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return sshPriv, err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return sshPriv, err
	}

	privatePem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		},
	)

	sshPriv, err = ssh.ParsePrivateKey(privatePem)
	if err != nil {
		return sshPriv, err
	}

	return sshPriv, nil

}
