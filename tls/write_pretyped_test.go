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

package tls

import (
	"bytes"
	"testing"
)

// WritePretyped 的往返：封出来的记录流，用同一套密钥解回来，明文要一模一样。
//
// 边界都过一遍：单记录、正好 16384、跨记录、多记录。只有**最后一条**记录
// 末尾带内层类型字节，前面的记录就是内容本身。
func TestWritePretypedRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 16)
	iv := bytes.Repeat([]byte{0x7f}, 12)

	for _, n := range []int{1, 100, 4096, 16380, 16384, 16385, 20000, 40000, 100000} {
		payload := bytes.Repeat([]byte("A"), n)
		typed := PreparePretyped(payload)
		if typed[len(typed)-1] != recordApplicationData {
			t.Fatalf("n=%d: PreparePretyped 没补类型字节", n)
		}

		send, err := newRecordProtector(trafficKeys{key: key, iv: iv})
		if err != nil {
			t.Fatal(err)
		}
		recv, err := newRecordProtector(trafficKeys{key: key, iv: iv})
		if err != nil {
			t.Fatal(err)
		}
		sm := &StateMachine{state: StateEstablished, writeKeys: send}

		out, err := sm.WritePretyped(typed)
		if err != nil {
			t.Fatalf("n=%d: WritePretyped: %v", n, err)
		}

		// 先把记录切出来（回调里拿不到"这是不是最后一条"）
		var recs []*Record
		parser := NewRecordParser()
		if _, err := parser.Parse(out, func(r *Record) error {
			cp := *r
			recs = append(recs, &cp)
			return nil
		}); err != nil {
			t.Fatalf("n=%d: 解记录流失败: %v", n, err)
		}

		var got []byte
		for i, r := range recs {
			if r.Type != recordApplicationData {
				t.Errorf("n=%d: 第 %d 条记录外层类型是 %d，要 %d", n, i, r.Type, recordApplicationData)
			}
			inner, typ, err := recv.openInto(nil, r.Payload)
			if err != nil {
				t.Fatalf("n=%d: 第 %d 条解密失败: %v", n, i, err)
			}
			// **每条记录**末尾都是类型字节（TLS 1.3 的要求，不是只有最后一条）
			if typ != recordApplicationData {
				t.Errorf("n=%d: 第 %d 条的内层类型是 %d，要 %d", n, i, typ, recordApplicationData)
			}
			got = append(got, inner[:len(inner)-1]...)
		}

		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: 解出来 %d 字节，对不上", n, len(got))
		}
		if want := (len(typed) + maxRecordPayload) / (maxRecordPayload + 1); len(recs) != want {
			t.Errorf("n=%d: 切出 %d 条记录，期望 %d", n, len(recs), want)
		}
	}
}
