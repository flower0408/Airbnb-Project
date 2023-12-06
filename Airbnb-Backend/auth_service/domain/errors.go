package domain

import (
	"fmt"
	"net/url"
	"time"
)

type ErrUnknown struct {
	InnerErr error
}

func (e ErrUnknown) Error() string {
	return fmt.Sprintf("unknown or unexpected error caused by: %s", e.InnerErr.Error())
}

type ErrClientSideTimeout struct {
	URL        string
	Method     string
	MaxTimeout time.Duration
}

func (e ErrClientSideTimeout) Error() string {
	return fmt.Sprintf("client-side timeout [max = %s] for request: HTTP %s\t%s", e.MaxTimeout, e.Method, e.URL)
}

type ErrRespTmp struct {
	URL        string
	Method     string
	StatusCode int
}

func (e ErrRespTmp) Error() string {
	return fmt.Sprintf("temporary error [status code %d] for request: HTTP %s\t%s", e.StatusCode, e.Method, e.URL)
}

// we consider all errors of ErrRespTmp type to be equal
// this helps retrier determine if it should send another request or not
func (e ErrRespTmp) Is(err error) bool {
	_, ok := err.(ErrRespTmp)
	return ok
}

type ErrResp struct {
	URL        string
	Method     string
	StatusCode int
}

func (e ErrResp) Error() string {
	return fmt.Sprintf("error [status code %d] for request: HTTP %s\t%s", e.StatusCode, e.Method, e.URL)
}

type ErrConnecting struct {
	Err *url.Error
}

func (e ErrConnecting) Error() string {
	return fmt.Sprintf("error connecting for request: HTTP %s\t%s\nInner error: %s", e.Err.Op, e.Err.URL, e.Err)
}

type ErrInternal struct {
	InnerErr error
}

func (e ErrInternal) Error() string {
	return e.InnerErr.Error()
}

type ErrCtxTimeoutl struct {
	Stack string
}

func (e ErrCtxTimeoutl) Error() string {
	return fmt.Sprintf("ctx timed out in: %s", e.Stack)
}
