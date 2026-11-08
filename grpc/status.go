// Copyright 2023-2024 antlabs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"fmt"
	"strconv"

	"github.com/antlabs/fio/http2"
)

// gRPC 的状态码（和 HTTP 状态码是两回事）。
//
// **这一点容易搞错**：gRPC 调用的成败不看 HTTP 状态码。一个"用户不存在"
// 的调用，HTTP 层面是 200 OK，gRPC 层面是 grpc-status: 5 (NOT_FOUND)。
// 状态在**响应末尾的 trailer** 里，不是在响应头里——因为服务端要先把
// 数据流式发出去，发到最后才知道结果。
type Code uint32

const (
	// OK 成功
	OK Code = 0
	// Canceled 调用方取消了
	Canceled Code = 1
	// Unknown 未知错误
	Unknown Code = 2
	// InvalidArgument 参数不合法（等价于 HTTP 400）
	InvalidArgument Code = 3
	// DeadlineExceeded 超时
	DeadlineExceeded Code = 4
	// NotFound 找不到（比如资源不存在）
	NotFound Code = 5
	// AlreadyExists 已经存在
	AlreadyExists Code = 6
	// PermissionDenied 没权限
	PermissionDenied Code = 7
	// ResourceExhausted 资源耗尽（限流、配额）
	ResourceExhausted Code = 8
	// FailedPrecondition 前置条件不满足
	FailedPrecondition Code = 9
	// Aborted 并发冲突（比如事务）
	Aborted Code = 10
	// OutOfRange 越界
	OutOfRange Code = 11
	// Unimplemented 没实现
	Unimplemented Code = 12
	// Internal 内部错误
	Internal Code = 13
	// Unavailable 服务不可用（等价于 HTTP 503）
	Unavailable Code = 14
	// DataLoss 数据丢了
	DataLoss Code = 15
	// Unauthenticated 没认证（等价于 HTTP 401）
	Unauthenticated Code = 16
)

func (c Code) String() string {
	switch c {
	case OK:
		return "OK"
	case Canceled:
		return "Canceled"
	case Unknown:
		return "Unknown"
	case InvalidArgument:
		return "InvalidArgument"
	case DeadlineExceeded:
		return "DeadlineExceeded"
	case NotFound:
		return "NotFound"
	case AlreadyExists:
		return "AlreadyExists"
	case PermissionDenied:
		return "PermissionDenied"
	case ResourceExhausted:
		return "ResourceExhausted"
	case FailedPrecondition:
		return "FailedPrecondition"
	case Aborted:
		return "Aborted"
	case OutOfRange:
		return "OutOfRange"
	case Unimplemented:
		return "Unimplemented"
	case Internal:
		return "Internal"
	case Unavailable:
		return "Unavailable"
	case DataLoss:
		return "DataLoss"
	case Unauthenticated:
		return "Unauthenticated"
	}
	return fmt.Sprintf("Code(%d)", uint32(c))
}

// grpc 那几个头的名字（规范里写死的）。
const (
	// headerContentType 必须是 application/grpc 开头
	headerContentType = "content-type"
	// headerStatus 是结果状态码，放在 trailer 里
	headerStatus = "grpc-status"
	// headerMessage 是人类可读的错误信息（可选的），也在 trailer 里
	headerMessage = "grpc-message"
	// headerTimeout 是调用方给的服务端超时
	headerTimeout = "grpc-timeout"
	// headerEncoding 是消息压缩方式
	headerEncoding = "grpc-encoding"
	// headerAcceptEncoding 是调用方能接受的压缩方式
	headerAcceptEncoding = "grpc-accept-encoding"
)

// ContentType 是 gRPC 的 content-type 前缀。
//
// 完整的是 "application/grpc" 或者带格式的
// "application/grpc+proto"；判断用前缀匹配。
const ContentType = "application/grpc"

// IsGRPCContentType 判断一个 content-type 是不是 gRPC。
func IsGRPCContentType(v string) bool {
	return len(v) >= len(ContentType) && v[:len(ContentType)] == ContentType
}

// Status 是一次调用的结果。
type Status struct {
	Code    Code
	Message string
}

// 常用的状态构造。
//
// **名字不能和 Code 的常量重名**（OK、Internal 这些已经是常量了），
// 所以用 StatusOK / StatusInternal 这种前缀。
//
// statusOK 是内部用的共享 OK 状态（只读）。不通过 StatusOK() 暴露共享
// 指针：调用方可能改 Message，共享会串数据。Finish 这种只读
// AppendStatus 的热路径用它省一次分配。
var statusOK = &Status{Code: OK}

func StatusOK() *Status                        { return &Status{Code: OK} }
func StatusNotFound(msg string) *Status        { return &Status{Code: NotFound, Message: msg} }
func StatusUnimplemented(msg string) *Status   { return &Status{Code: Unimplemented, Message: msg} }
func StatusInternal(msg string) *Status        { return &Status{Code: Internal, Message: msg} }
func StatusInvalidArgument(msg string) *Status { return &Status{Code: InvalidArgument, Message: msg} }

// Error 实现 error 接口，Code 不是 OK 的时候用它。
func (s *Status) Error() string {
	if s == nil || s.Code == OK {
		return ""
	}
	if s.Message == "" {
		return "rpc error: code = " + s.Code.String()
	}
	return "rpc error: code = " + s.Code.String() + " desc = " + s.Message
}

// StatusFromHeaders 从 trailer 的头里解出状态。
//
// trailer 里没 grpc-status 的话按 Unknown 处理——规范要求必须有，
// 没有说明对端不按规矩来。
func StatusFromHeaders(headers []http2.HeaderField) *Status {
	s := &Status{Code: Unknown, Message: "missing grpc-status in trailer"}
	for _, h := range headers {
		switch h.Name {
		case headerStatus:
			n, err := strconv.ParseUint(h.Value, 10, 32)
			if err != nil {
				s.Code = Unknown
				s.Message = "malformed grpc-status: " + h.Value
				return s
			}
			s.Code = Code(n)
			s.Message = ""
		case headerMessage:
			// grpc-message 是 percent-encoded 的（RFC 3986）
			s.Message = percentDecode(h.Value)
		}
	}
	return s
}

// AppendStatus 把状态拼成 trailer 的头。
func AppendStatus(dst []http2.HeaderField, s *Status) []http2.HeaderField {
	code := OK
	if s != nil {
		code = s.Code
	}
	dst = append(dst, http2.HeaderField{
		Name:  headerStatus,
		Value: strconv.FormatUint(uint64(code), 10),
	})
	if s != nil && s.Message != "" {
		dst = append(dst, http2.HeaderField{
			Name:  headerMessage,
			Value: percentEncode(s.Message),
		})
	}
	return dst
}

// percentDecode 解 grpc-message 的 percent-encoding。
//
// 为什么 trailer 里的消息要编码：HTTP/2 的头值不能带任意字节（只有
// 可见 ASCII + 空格），而错误信息里可能有换行、中文、二进制。规范定的
// 办法是把不能直接放的那些转成 %XX。
func percentDecode(s string) string {
	// 没有 % 就直接返回，省一次分配（绝大多数错误信息是纯 ASCII）
	hasPercent := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			hasPercent = true
			break
		}
	}
	if !hasPercent {
		return s
	}

	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			out = append(out, s[i])
			continue
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			out = append(out, s[i])
			continue
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return string(out)
}

// percentEncode 把不能在头值里直接放的字节转成 %XX。
func percentEncode(s string) string {
	// 全是可打印 ASCII 就不用转
	need := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			need = true
			break
		}
	}
	if !need {
		return s
	}

	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			out = append(out, '%', hexDigits[c>>4], hexDigits[c&0xf])
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
