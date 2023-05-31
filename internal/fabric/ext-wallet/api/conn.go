package handlers

type WalletApiHandler struct {
	addr  string
	mspId string
}

func NewWalletApiHandler(addr string, mspId string) *WalletApiHandler {
	return &WalletApiHandler{
		addr,
		mspId,
	}
}
