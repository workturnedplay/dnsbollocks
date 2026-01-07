//go:build windows

// Copyright 2026 workturnedplay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsbollocks

import "testing"

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.co", "example.com", false},
		{"example.com", "example.co", false},
		{"*example.com", "example.com", true},
		{"*example.com", ".example.com", false},
		{"*example.com", "fexample.com", true},
		{"*example.com", "fghexample.com", true},
		{"?example.com", "fexample.com", true},
		{"?example.com", "fghexample.com", false},
		{"?.example.com", "f.example.com", true},
		{"?.example.com", "fg.example.com", false},
		{"example.com", "example.com.", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "foo.bar.example.com", false},
		{"**.example.com", "foo.bar.example.com", true},
		{"**.example.com", "example.com", false},
		{"**.example.com", ".example.com", true}, // should use {**} here as a user, footgun here.
		{"{**}.example.com", "f.example.com", true},
		{"{**}.example.com", "abc.def.example.com", true},
		{"{**}.example.com", ".example.com", false},
		{"?", "a", true},
		{"?", "ab", false},
		{"!", ".", true},
		{"!", "a", true},
		{"!", "ab", false},
		{"{*}", "ab", true},
		{"*", "ab", true},
		{"{*}", "a", true},
		{"*", "a", true},
		{"{*}", "", false},
		{"*", "", true},
		{"a{*}c", "abc", true},
		{"a{*}c", "a.c", false},
		{"a{**}c", "a.c", true},
		{"a*c", "abc", true},
		{"a{*}c", "abdc", true},
		{"a{**}c", "ab.c", true},
		{"a{**}c", "a.dc", true},
		{"a*c", "abdc", true},
		{"a{*}c", "ac", false},
		{"a*c", "ac", true},
		{"a*c", "a.c", false},
		{"a*.c", "a.c", true},
		{"a*.c", "ab.c", true},
		{"a*.c", "abd.c", true},
		{"a{*}.c", "a.c", false},
		{"a{*}.c", "ab.c", true},
		{"a{*}.c", "abd.c", true},
		{"foo.?ar.com", "foo.bar.com", true},
		{"foo.?ar.com", "foo.xar.com", true},
		{"foo.?ar.com", "foo.xxar.com", false},
		{"foo!?ar.com", "foo.bar.com", true},
		{"foo!!ar.com", "foo.bar.com", true},
		{"foo!!ar.com", "foodbar.com", true},
		{"sdmntpr*.oaiusercontent.com", "sdmntpritalynorth.oaiusercontent.com", true},
	}

	for _, tt := range tests {
		if got := matchPattern(tt.pattern, tt.name); got != tt.want {
			t.Fatalf("matchPattern(%q, %q) = %v, want %v",
				tt.pattern, tt.name, got, tt.want)
		}
	}
}
