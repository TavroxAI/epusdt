package http_client

import (
	"time"

	"github.com/GMWalletApp/epusdt/util/security"
	"github.com/go-resty/resty/v2"
)

// ClientFactory is overridden in tests to stub outbound HTTP calls.
var ClientFactory = resty.New

// CallbackClientFactory builds the client used to deliver merchant callbacks
// (notify_url). Tests override it the same way as ClientFactory.
var CallbackClientFactory = NewCallbackClient

// GetHttpClient 获取请求客户端
//
// This client is for operator-configured endpoints (rate API, payment provider
// APIs); its destination is trusted configuration, not merchant input.
func GetHttpClient(proxys ...string) *resty.Client {
	client := ClientFactory()
	// 如果有代理
	if len(proxys) > 0 {
		proxy := proxys[0]
		client.SetProxy(proxy)
	}
	client.SetTimeout(time.Second * 10)
	return client
}

// NewCallbackClient builds a client whose destination is merchant-controlled.
func NewCallbackClient() *resty.Client {
	client := resty.NewWithClient(security.NewSafeHTTPClient(10 * time.Second))
	client.SetTimeout(time.Second * 10)
	return client
}

// GetCallbackClient returns the client used for merchant callback delivery
// (notify_url). It carries the outbound policy: the resolved dial address must be
// public, and every redirect hop is re-validated. Applying the policy here rather
// than only when notify_url is stored is what closes the redirect and rebinding
// holes: the store-time check sees a URL, the client sees the address it actually
// connects to.
func GetCallbackClient() *resty.Client {
	return CallbackClientFactory()
}
