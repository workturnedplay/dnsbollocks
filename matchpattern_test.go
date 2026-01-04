package main

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
		{"**.example.com", ".example.com", true}, //should use {**} here as a user, footgun here.
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
