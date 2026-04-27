package main

import (
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
)

func main() {
	// 1. Initialize the file set
	fset := token.NewFileSet()

	// 2. Parse the source file (replace 'main.go' with your actual filename)
	// We use parser.ParseComments so the AST initially "sees" them
	f, err := parser.ParseFile(fset, "../../internal/dnsbollocks/platform_windows.go", nil, parser.ParseComments)
	if err != nil {
		log.Fatal("Error parsing source:", err)
	}

	//// 3. Strip all comments from the Abstract Syntax Tree
	//f.Comments = nil
	// Filter the comments
	var cleanComments []*ast.CommentGroup
	for _, group := range f.Comments {
		keepGroup := false
		for _, c := range group.List {
			txt := c.Text
			// The fix: Check for both //go: and the older // +build 
			// and ensure we catch them even if the parser slightly tweaked the string
			if strings.Contains(txt, "//go:") || strings.Contains(txt, "// +build") {
				keepGroup = true
				break
			}
		}

		if keepGroup {
			cleanComments = append(cleanComments, group)
		}
	}

	// Replace original comments with our filtered list
	f.Comments = cleanComments

	// 4. Create the output file
	outFile, err := os.Create("tmpnocomments.go")
	if err != nil {
		log.Fatal("Error creating file:", err)
	}
	defer outFile.Close()

	// 5. Format the "clean" AST and write it to the file
	err = format.Node(outFile, fset, f)
	if err != nil {
		log.Fatal("Error writing output:", err)
	}

	println("Success! Comments stripped to .\tmpnocomments.go")
}
