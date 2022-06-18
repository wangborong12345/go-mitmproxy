package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	log "github.com/sirupsen/logrus"
)

// 拦截 https 流量通用接口
type interceptor interface {
	// 初始化
	Start() error
	// 传入当前客户端 req
	Dial(req *http.Request) (net.Conn, error)
}

// 直接转发 https 流量
type forward struct{}

func (i *forward) Start() error {
	return nil
}

func (i *forward) Dial(req *http.Request) (net.Conn, error) {
	return net.Dial("tcp", req.Host)
}

// 模拟了标准库中 server 运行，目的是仅通过当前进程内存转发 socket 数据，不需要经过 tcp 或 unix socket

type pipeAddr struct {
	remoteAddr string
}

func (pipeAddr) Network() string   { return "pipe" }
func (a *pipeAddr) String() string { return a.remoteAddr }

// add Peek method for conn
type pipeConn struct {
	net.Conn
	r           *bufio.Reader
	host        string // server host:port
	remoteAddr  string // client ip:port
	connContext *ConnContext
}

func newPipeConn(c net.Conn, req *http.Request) *pipeConn {
	connContext := req.Context().Value(connContextKey).(*ConnContext)
	pipeConn := &pipeConn{
		Conn:        c,
		r:           bufio.NewReader(c),
		host:        req.Host,
		remoteAddr:  req.RemoteAddr,
		connContext: connContext,
	}
	connContext.pipeConn = pipeConn
	return pipeConn
}

func (c *pipeConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *pipeConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *pipeConn) RemoteAddr() net.Addr {
	return &pipeAddr{remoteAddr: c.remoteAddr}
}

// 建立客户端和服务端通信的通道
func newPipes(req *http.Request) (net.Conn, *pipeConn) {
	client, srv := net.Pipe()
	server := newPipeConn(srv, req)
	return client, server
}

// mock net.Listener
type middleListener struct {
	connChan chan net.Conn
}

func (l *middleListener) Accept() (net.Conn, error) { return <-l.connChan, nil }
func (l *middleListener) Close() error              { return nil }
func (l *middleListener) Addr() net.Addr            { return nil }

// middle: man-in-the-middle server
type middle struct {
	proxy    *Proxy
	ca       *cert.CA
	listener *middleListener
	server   *http.Server
}

func newMiddle(proxy *Proxy) (interceptor, error) {
	ca, err := cert.NewCA(proxy.Opts.CaRootPath)
	if err != nil {
		return nil, err
	}

	m := &middle{
		proxy: proxy,
		ca:    ca,
		listener: &middleListener{
			connChan: make(chan net.Conn),
		},
	}

	server := &http.Server{
		Handler: m,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*tls.Conn).NetConn().(*pipeConn).connContext)
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
		TLSConfig: &tls.Config{
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				log.Debugf("middle GetCertificate ServerName: %v\n", clientHello.ServerName)
				return ca.GetCert(clientHello.ServerName)
			},
		},
	}
	m.server = server
	return m, nil
}

func (m *middle) Start() error {
	return m.server.ServeTLS(m.listener, "", "")
}

func (m *middle) Dial(req *http.Request) (net.Conn, error) {
	pipeClientConn, pipeServerConn := newPipes(req)
	err := pipeServerConn.connContext.initServerTcpConn()
	if err != nil {
		pipeClientConn.Close()
		pipeServerConn.Close()
		return nil, err
	}
	go m.intercept(pipeServerConn)
	return pipeClientConn, nil
}

func (m *middle) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		// wss
		defaultWebSocket.wss(res, req)
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	m.proxy.ServeHTTP(res, req)
}

// 解析 connect 流量
// 如果是 tls 流量，则进入 listener.Accept => Middle.ServeHTTP
// 否则很可能是 ws 流量
func (m *middle) intercept(pipeServerConn *pipeConn) {
	buf, err := pipeServerConn.Peek(3)
	if err != nil {
		log.Errorf("Peek error: %v\n", err)
		pipeServerConn.Close()
		return
	}

	// https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py is_tls_record_magic
	if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03 {
		// tls
		pipeServerConn.connContext.ClientConn.Tls = true
		pipeServerConn.connContext.initHttpsServerConn()
		m.listener.connChan <- pipeServerConn
	} else {
		// ws
		defaultWebSocket.ws(pipeServerConn, pipeServerConn.host)
	}
}
