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

package qpack

// staticTableEntries 是 RFC 9204 附录 A 的静态表：99 项，下标就是索引。
//
// 这张表是协议的一部分（像 HTTP/2 的 HPACK 静态表一样钉死在 RFC 里），
// 数据照抄 RFC；表项里的名字是大小写敏感的。
var staticTableEntries = [...]HeaderField{
	{Name: ":authority"},
	{Name: ":path", Value: "/"},
	{Name: "age", Value: "0"},
	{Name: "content-disposition"},
	{Name: "content-length", Value: "0"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "referer"},
	{Name: "set-cookie"},
	{Name: ":method", Value: "CONNECT"},
	{Name: ":method", Value: "DELETE"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "HEAD"},
	{Name: ":method", Value: "OPTIONS"},
	{Name: ":method", Value: "POST"},
	{Name: ":method", Value: "PUT"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "103"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "503"},
	{Name: "accept", Value: "*/*"},
	{Name: "accept", Value: "application/dns-message"},
	{Name: "accept-encoding", Value: "gzip, deflate, br"},
	{Name: "accept-ranges", Value: "bytes"},
	{Name: "access-control-allow-headers", Value: "cache-control"},
	{Name: "access-control-allow-headers", Value: "content-type"},
	{Name: "access-control-allow-origin", Value: "*"},
	{Name: "cache-control", Value: "max-age=0"},
	{Name: "cache-control", Value: "max-age=2592000"},
	{Name: "cache-control", Value: "max-age=604800"},
	{Name: "cache-control", Value: "no-cache"},
	{Name: "cache-control", Value: "no-store"},
	{Name: "cache-control", Value: "public, max-age=31536000"},
	{Name: "content-encoding", Value: "br"},
	{Name: "content-encoding", Value: "gzip"},
	{Name: "content-type", Value: "application/dns-message"},
	{Name: "content-type", Value: "application/javascript"},
	{Name: "content-type", Value: "application/json"},
	{Name: "content-type", Value: "application/x-www-form-urlencoded"},
	{Name: "content-type", Value: "image/gif"},
	{Name: "content-type", Value: "image/jpeg"},
	{Name: "content-type", Value: "image/png"},
	{Name: "content-type", Value: "text/css"},
	{Name: "content-type", Value: "text/html; charset=utf-8"},
	{Name: "content-type", Value: "text/plain"},
	{Name: "content-type", Value: "text/plain;charset=utf-8"},
	{Name: "range", Value: "bytes=0-"},
	{Name: "strict-transport-security", Value: "max-age=31536000"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains; preload"},
	{Name: "vary", Value: "accept-encoding"},
	{Name: "vary", Value: "origin"},
	{Name: "x-content-type-options", Value: "nosniff"},
	{Name: "x-xss-protection", Value: "1; mode=block"},
	{Name: ":status", Value: "100"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "302"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "403"},
	{Name: ":status", Value: "421"},
	{Name: ":status", Value: "425"},
	{Name: ":status", Value: "500"},
	{Name: "accept-language"},
	{Name: "access-control-allow-credentials", Value: "FALSE"},
	{Name: "access-control-allow-credentials", Value: "TRUE"},
	{Name: "access-control-allow-headers", Value: "*"},
	{Name: "access-control-allow-methods", Value: "get"},
	{Name: "access-control-allow-methods", Value: "get, post, options"},
	{Name: "access-control-allow-methods", Value: "options"},
	{Name: "access-control-expose-headers", Value: "content-length"},
	{Name: "access-control-request-headers", Value: "content-type"},
	{Name: "access-control-request-method", Value: "get"},
	{Name: "access-control-request-method", Value: "post"},
	{Name: "alt-svc", Value: "clear"},
	{Name: "authorization"},
	{Name: "content-security-policy", Value: "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{Name: "early-data", Value: "1"},
	{Name: "expect-ct"},
	{Name: "forwarded"},
	{Name: "if-range"},
	{Name: "origin"},
	{Name: "purpose", Value: "prefetch"},
	{Name: "server"},
	{Name: "timing-allow-origin", Value: "*"},
	{Name: "upgrade-insecure-requests", Value: "1"},
	{Name: "user-agent"},
	{Name: "x-forwarded-for"},
	{Name: "x-frame-options", Value: "deny"},
	{Name: "x-frame-options", Value: "sameorigin"},
}

// staticByName 是"名字 -> 静态表里第一个用这个名字的索引"。
//
// 编码"带名引用"的字面量时用它：表里同名多项的（:method、:status、
// content-type…）随便引一个都行——引用的是**名字**，值是另发的。
// 取最小的那个（:method 是 16，:status 是 25）。
var staticByName = func() map[string]uint64 {
	m := make(map[string]uint64, len(staticTableEntries))
	for i := len(staticTableEntries) - 1; i >= 0; i-- {
		m[staticTableEntries[i].Name] = uint64(i)
	}
	return m
}()

// staticByField 是完整匹配（名字 + 值都在表里）的索引，编码成"索引字段行"。
// 键用 name + "\x00" + value，名字里不会有 NUL，拼不进歧义。
var staticByField = func() map[string]uint64 {
	m := make(map[string]uint64, len(staticTableEntries))
	for i, e := range staticTableEntries {
		m[e.Name+"\x00"+e.Value] = uint64(i)
	}
	return m
}()
