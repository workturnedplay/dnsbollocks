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

	// 1. Check for the flag
	// // Usage: go run stripper.go --preserve
	// preserveLines := false
	// if len(os.Args) > 1 && os.Args[1] == "--preserve-line-numbers" {
	// preserveLines = true
	// }

	// 1. Initialize the file set
	fset := token.NewFileSet()

	// 2. Parse the source file (replace 'main.go' with your actual filename)
	// We use parser.ParseComments so the AST initially "sees" them
	f, err := parser.ParseFile(fset, inputPath, nil, parser.ParseComments)
	if err != nil {
		log.Fatal("Error parsing source:", err)
	}

	// //// 3. Strip all comments from the Abstract Syntax Tree
	// //f.Comments = nil
	// // Filter the comments
	// var cleanComments []*ast.CommentGroup
	// for _, group := range f.Comments {
	// keepGroup := false
	// for _, c := range group.List {
	// txt := strings.TrimSpace(c.Text)
	// // The fix: Check for both //go: and the older // +build
	// // and ensure we catch them even if the parser slightly tweaked the string
	// if strings.Contains(txt, "//go:") || strings.Contains(txt, "// +build") {
	// keepGroup = true
	// break
	// }
	// }

	// if keepGroup {
	// cleanComments = append(cleanComments, group)
	// }
	// }

	// // // Replace original comments with our filtered list
	// // f.Comments = cleanComments
	// for _, group := range f.Comments {
	// for _, c := range group.List {
	// // 1. Get the raw text (e.g., "  //  go:generate  ")
	// raw := c.Text

	// // 2. Left-trim whitespace and the slashes to see the "core"
	// // This handles "  //  go:..."
	// core := strings.TrimLeft(raw, " /")

	// // 3. We only care if the core starts with "go:" or is the old build tag
	// // Note: we don't trim spaces *inside* the core
	// isDirective := strings.HasPrefix(core, "go:") || strings.HasPrefix(core, "+build")

	// if !isDirective {
	// // Check if it's a block comment /* ... */
	// if strings.HasPrefix(c.Text, "/*") {
	// // Count newlines to keep vertical spacing
	// lineCount := strings.Count(c.Text, "\n")
	// if lineCount == 0 {
	// // Inline block: Keep it on one line!
	// c.Text = "/*.*/"
	// } else {
	// // Multi-line block: Keep the newlines inside the /* */
	// c.Text = "/*." + strings.Repeat("\n.", lineCount) + "*/"
	// }
	// // // We want to keep every newline, but replace everything else
	// // // This preserves the EXACT shape of the block
	// // lines := strings.Split(c.Text, "\n")
	// // for i := range lines {
	// // if i == 0 {
	// // lines[i] = "/* ." // Keep start
	// // } else if i == len(lines)-1 {
	// // lines[i] = " . */" // Keep end
	// // } else {
	// // lines[i] = " . " // Middle lines
	// // }
	// // }
	// // c.Text = strings.Join(lines, "\n")
	// } else {
	// // Regular line comment //
	// c.Text = "//."
	// }
	// } else {
	// // It's a directive! Keep it exactly as it was.
	// }
	// }
	// }

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
		if _, err := os.Stat(*outPath); err == nil && !*overwrite {
			log.Fatalf("File '%s' already exists. Use -y to overwrite.", *outPath)
		}

		f, err := os.Create(*outPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		output = f
	}

	// // 4. Create the output file
	// outFile, err := os.Create("tmpnocomments.go")
	// if err != nil {
	// log.Fatal("Error creating file:", err)
	// }
	// defer outFile.Close()

	// 5. Format the "clean" AST and write it to the file
	err = format.Node(output, fset, f)
	if err != nil {
		log.Fatal("Error writing output:", err)
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
