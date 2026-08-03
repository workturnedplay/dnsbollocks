package main

import (
	"flag"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	// 1. Define Flags
	outPath := flag.String("o", "", "Output file path (default: stdout)")
	overwrite := flag.Bool("y", false, "Overwrite output file if it exists")
	preserveLines := flag.Bool("preserve-line-numbers", false, "Preserve line count (bit-identical mode)")
	flag.Parse()

	// Ensure we have a source file to read (remaining arg after flags)
	if flag.NArg() < 1 {
		log.Fatal("Usage: stripper [-o output.go] [-y] [--preserve-line-numbers] <input.go>")
	}
	inputPath := flag.Arg(0)

	// 1. Initialize the file set
	fset := token.NewFileSet()

	// 2. Parse the source file (replace 'main.go' with your actual filename)
	// We use parser.ParseComments so the AST initially "sees" them
	f, err1 := parser.ParseFile(fset, inputPath, nil, parser.ParseComments)
	if err1 != nil {
		log.Fatal("Error parsing source:", err1)
	}

	// 2. Logic Selection
	if *preserveLines {
		println("Mode: Preserve Lines (Bit-Identical Build)")
		applyPreserveLogic(f)
	} else {
		println("Mode: Total Strip (Smaller Source File)")
		applyStripLogic(f)
	}

	// 3. Output Destination Logic
	var output io.Writer = os.Stdout

	if *outPath != "" {
		// Check if file exists
		if _, err2 := os.Stat(*outPath); err2 == nil && !*overwrite {
			log.Fatalf("File '%s' already exists. Use -y to overwrite.", *outPath)
		}

		f, err3 := os.Create(*outPath)
		if err3 != nil {
			log.Fatal(err3)
		}
		defer f.Close()
		output = f
	}

	// 5. Format the "clean" AST and write it to the file
	err1 = format.Node(output, fset, f)
	if err1 != nil {
		log.Panic("Error writing output:", err1)
	}
	//println("Success! Comments stripped to .\tmpnocomments.go")
}

func applyPreserveLogic(f *ast.File) {
	// VARIANT A: Blank out comments but keep the objects (Preserves Lines)
	// 2. Modify comments with character-level precision
	for _, group := range f.Comments {
		for _, c := range group.List {
			// Check for directives (go: or +build)
			core := strings.TrimLeft(c.Text, " /")
			if strings.HasPrefix(core, "go:") || strings.HasPrefix(core, "+build") {
				continue
			}

			if strings.HasPrefix(c.Text, "//") {
				// Line comments: always become a single line
				c.Text = "//."
			} else if strings.HasPrefix(c.Text, "/*") {
				// Block comments: map original newlines to new newlines
				old := c.Text
				var sb strings.Builder
				sb.WriteString("/*")

				// Strip the /* and */ wrappers for processing
				content := old[2 : len(old)-2]

				// If there is any content, put a dot on the first line
				if len(content) > 0 && content[0] != '\n' {
					sb.WriteByte('.')
				}

				for i := 0; i < len(content); i++ {
					if content[i] == '\n' {
						sb.WriteByte('\n')
						// If there's content after the newline, put a dot
						// but check if it's not just another newline
						if i+1 < len(content) && content[i+1] != '\n' {
							sb.WriteByte('.')
						}
					}
				}
				sb.WriteString("*/")
				c.Text = sb.String()
			}
		}
	}
}

func applyStripLogic(f *ast.File) {
	// VARIANT B: Filter the slice (Actually removes the lines)
	var cleanComments []*ast.CommentGroup
	for _, group := range f.Comments {
		keepGroup := false
		for _, c := range group.List {
			core := strings.TrimLeft(c.Text, " /")
			if strings.HasPrefix(core, "go:") || strings.HasPrefix(core, "+build") {
				keepGroup = true
				break
			}
		}
		if keepGroup {
			cleanComments = append(cleanComments, group)
		}
	}
	f.Comments = cleanComments
}
