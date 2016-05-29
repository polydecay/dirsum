package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/urfave/cli"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	IsTerminal bool = false
	TermWidth  int  = 80
)

var AppHelpTemplate = ` Usage: {{.Usage}}

 Commands:{{range .Categories}}{{range .Commands}}
   {{.Name}}{{range .Aliases}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}{{end}}{{end}}

 Global Options:{{range .Flags}}
   {{.}}{{end}}

 Note: use 'dirsum <command> -h' to show help for specific commands

`

// Abuse the commands description for positional arguments.
var CommandHelpTemplate = ` Usage: dirsum [global options] {{.Name}} {{if .Flags}}[options] {{end}}{{.Description}}{{if .Flags}}

 Options:{{range .Flags}}
   {{.}}{{end}}{{end}}

`

// -------------------------------------------------------------------
// Types

type ProgressReader struct {
	Reader     io.Reader
	TotalBytes int64
	readBytes  int64
	lastDraw   time.Time
}

func (r *ProgressReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.readBytes += int64(n)

	// Postpone the first draw to prevent excessive updating for small files.
	if r.lastDraw.IsZero() {
		r.lastDraw = time.Now().Add(time.Millisecond * 250)
	}

	// Update progress if its been more than 150ms since last draw.
	if err == nil && r.lastDraw.Add(time.Millisecond*150).Before(time.Now()) {
		progress := float64(r.readBytes) / float64(r.TotalBytes) * 100
		fmt.Printf(" %.f%%\r", progress)
		r.lastDraw = time.Now()
	} else if err == io.EOF {
		// Clear the progress.
		fmt.Printf("     \r")
	}

	return n, err
}

type Checksum struct {
	Hash string
	Path string
}

func (c *Checksum) Verify() (bool, error) {
	newHash, err := generateMd5(c.Path)
	if err != nil {
		return false, err
	}

	if c.Hash == newHash {
		return true, nil
	}

	return false, nil
}

func (c *Checksum) String() string {
	return fmt.Sprintf("%v *%v", c.Hash, c.Path)
}

type Checksums []Checksum

func (slice Checksums) Len() int {
	return len(slice)
}

func (slice Checksums) Less(a, b int) bool {
	aDir := strings.ToLower(filepath.Dir(slice[a].Path))
	bDir := strings.ToLower(filepath.Dir(slice[b].Path))

	if aDir == bDir {
		return strings.ToLower(slice[a].Path) < strings.ToLower(slice[b].Path)
	}

	return aDir < bDir
}

func (slice Checksums) Swap(a, b int) {
	slice[a], slice[b] = slice[b], slice[a]
}

// -------------------------------------------------------------------
// Functions

func readFile(path string) (Checksums, error) {
	var sums Checksums

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return sums, err
	}

	r := regexp.MustCompile(`^[0-9a-fA-F]{32} \*.*$`)
	dir := filepath.Dir(path)

	// Replace CRLF line endings with LF and split on each line.
	lines := strings.Split(strings.Replace(string(data), "\r\n", "\n", -1), "\n")
	for _, line := range lines {
		if len(line) <= 0 {
			continue
		}

		// Only process valid lines and ignore everything else.
		if r.MatchString(line) {
			split := strings.Split(line, " *")
			// Append the file path to relative checksums to make sure they are
			// relative to the current working directory.
			if !filepath.IsAbs(split[1]) {
				split[1] = filepath.Join(dir, split[1])
			}

			sums = append(sums, Checksum{
				Hash: split[0],
				Path: split[1],
			})
		}
	}

	return sums, nil
}

func readFileToMap(path string) (map[string]Checksum, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	r := regexp.MustCompile(`^[0-9a-fA-F]{32} \*.*$`)

	dir := filepath.Dir(path)
	var checksumMap map[string]Checksum
	checksumMap = make(map[string]Checksum)

	// Replace CRLF line endings with LF and split on each line.
	lines := strings.Split(strings.Replace(string(data), "\r\n", "\n", -1), "\n")
	for _, line := range lines {
		if len(line) <= 0 {
			continue
		}

		// Only process valid lines and ignore everything else.
		if r.MatchString(line) {
			split := strings.Split(line, " *")
			// Append the file path to relative checksums to make sure they are
			// relative to the current working directory.
			if !filepath.IsAbs(split[1]) {
				split[1] = filepath.Join(dir, split[1])
			}

			checksumMap[split[1]] = Checksum{split[0], split[1]}
		}
	}

	return checksumMap, nil
}

func writeFile(sums Checksums, path string) error {
	dir := filepath.Dir(path)
	var output bytes.Buffer

	sort.Sort(sums)
	for _, sum := range sums {
		// Make the checksum path relative to the output file.
		relPath, err := filepath.Rel(dir, sum.Path)
		if err != nil {
			// Use an absolute path if it could not be made relative.
			relPath, err = filepath.Abs(sum.Path)
			if err != nil {
				return err
			}
		}

		output.WriteString(fmt.Sprintf("%v *%v\n", sum.Hash, relPath))
	}

	return ioutil.WriteFile(path, output.Bytes(), 0644)
}

func generateMd5(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if IsTerminal {
		fileInfo, err := file.Stat()
		if err != nil {
			return "", err
		}

		pReader := &ProgressReader{
			Reader:     file,
			TotalBytes: fileInfo.Size(),
		}

		fmt.Printf(" >>  %s\r", ellipsize(filepath.Base(path), TermWidth-6))
		defer fmt.Printf("%s\r", strings.Repeat(" ", TermWidth-1))

		if _, err := io.Copy(hash, pReader); err != nil {
			return "", err
		}
	} else {
		if _, err := io.Copy(hash, file); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func verifyFile(path string) {
	sums, err := readFile(path)
	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n", err), color.FgRed)
		return
	}

	hasErrors := false
	for _, c := range sums {
		isValid, err := c.Verify()

		if !isValid {
			if !hasErrors {
				hasErrors = true
				printColored(fmt.Sprintf(" ER: %v\n", path), color.FgRed)
			}

			if err != nil {
				printColored(fmt.Sprintf("   Error: %v\n", c.Path), color.FgRed)
			} else {
				printColored(fmt.Sprintf("   Invalid: %v\n", c.Path), color.FgRed)
			}
		}
	}

	if !hasErrors {
		printColored(fmt.Sprintf(" OK: %v\n", path), color.FgGreen)
	}
}

// -------------------------------------------------------------------
// Printing

func ellipsize(s string, maxLength int) string {
	if utf8.RuneCountInString(s) > maxLength {
		var index int
		for runeIndex := range s {
			index++
			if index > maxLength-1 {
				return s[:runeIndex] + "…"
			}
		}
	}

	return s
}

func printColored(s string, clr color.Attribute) {
	if !IsTerminal {
		fmt.Print(s)
		return
	}

	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = ellipsize(lines[i], TermWidth-1)
	}

	// Print to color.Output for color support on Windows.
	put := color.New(clr).SprintFunc()
	fmt.Fprint(color.Output, put(strings.Join(lines, "\n")))
}

func sprintfHeader(format string, a ...interface{}) string {
	title := ellipsize(fmt.Sprintf(format, a...), TermWidth-2)
	return fmt.Sprintf("\n %v\n %v\n", title, strings.Repeat("-", TermWidth-2))
}

// -------------------------------------------------------------------
// Commands

func newCommand(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		fmt.Println("Incorrect Usage.\n")
		cli.ShowSubcommandHelp(ctx)
		return nil
	}

	source, output := ctx.Args()[0], ctx.Args()[1]
	outputBase := filepath.Base(output)
	fmt.Print(sprintfHeader("Hashing: %v", source))

	var sums Checksums
	err := filepath.Walk(source, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		// Exclude the output file from the sourceMap.
		if strings.HasSuffix(path, outputBase) {
			pathAbs, err := filepath.Abs(path)
			if err != nil {
				return err
			}

			outputAbs, err := filepath.Abs(output)
			if err != nil {
				return err
			}

			if pathAbs == outputAbs {
				return nil
			}
		}

		hash, err := generateMd5(path)
		if err != nil {
			return err
		}

		sums = append(sums, Checksum{hash, path})
		return nil
	})

	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	err = writeFile(sums, output)
	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	printColored(fmt.Sprintf(" Wrote: %v\n\n", output), color.FgGreen)
	return nil
}

func updateCommand(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		fmt.Println("Incorrect Usage.\n")
		cli.ShowSubcommandHelp(ctx)
		return nil
	}

	source, target := ctx.Args()[0], ctx.Args()[1]
	targetBase := filepath.Base(target)
	fmt.Print(sprintfHeader("Updating: %v", target))

	// Get new files from the source path.
	var sourceMap map[string]bool
	sourceMap = make(map[string]bool)
	err := filepath.Walk(source, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		// Exclude the output file from the sourceMap.
		if strings.HasSuffix(path, targetBase) {
			pathAbs, err := filepath.Abs(path)
			if err != nil {
				return err
			}

			targetAbs, err := filepath.Abs(target)
			if err != nil {
				return err
			}

			if pathAbs == targetAbs {
				return nil
			}
		}

		sourceMap[path] = true
		return nil
	})

	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	// Get current checksums from the target file.
	targetMap, err := readFileToMap(target)
	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	// Remove old checksums from the target map.
	if ctx.Bool("delete") {
		for key, _ := range targetMap {
			if _, ok := sourceMap[key]; !ok {
				delete(targetMap, key)
			}
		}

	}

	// Insert new checksum in the target map.
	for key, _ := range sourceMap {
		if _, ok := targetMap[key]; !ok {
			hash, err := generateMd5(key)
			if err != nil {
				printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
				os.Exit(1)
			}

			targetMap[key] = Checksum{hash, key}
		}
	}

	var targetSlice Checksums
	targetSlice = make(Checksums, 0, len(targetMap))
	for _, sum := range targetMap {
		targetSlice = append(targetSlice, sum)
	}

	err = writeFile(targetSlice, target)
	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	printColored(fmt.Sprintf(" Updated: %v\n\n", target), color.FgGreen)
	return nil
}

func verifyCommand(ctx *cli.Context) error {
	if len(ctx.Args()) < 1 {
		fmt.Println("Incorrect Usage.\n")
		cli.ShowSubcommandHelp(ctx)
		return nil
	}

	path := ctx.Args()[0]
	fmt.Print(sprintfHeader("Veryfing: %v", path))

	fileInfo, err := os.Stat(path)
	if err != nil {
		printColored(fmt.Sprintf(" Error: %v\n\n", err), color.FgRed)
		os.Exit(1)
	}

	if fileInfo.IsDir() {
		filepath.Walk(path, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				printColored(fmt.Sprintf(" Error: %v\n", err), color.FgRed)
				return nil
			}

			if strings.HasSuffix(path, ".md5") && !fi.IsDir() {
				verifyFile(path)
			}

			return nil
		})
	} else {
		verifyFile(path)
	}

	fmt.Print("\n")
	return nil
}

// -------------------------------------------------------------------
// Entry Point

func main() {
	// Override cli's default help message template.
	cli.AppHelpTemplate = AppHelpTemplate
	cli.CommandHelpTemplate = CommandHelpTemplate

	app := cli.NewApp()
	app.Name = "dirsum"
	app.Version = "0.0.1"
	app.Usage = "dirsum [global options] <command> ..."

	// GLobal flags.
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "no-colors, c",
			Usage:       "disable colored output",
			Destination: &color.NoColor,
		},
	}

	// Initialize global variables before executing commands.
	app.Before = func(ctx *cli.Context) error {
		// Check if stdout is a terminal and attempt to get the terminal width.
		fd := int(os.Stdout.Fd())
		if terminal.IsTerminal(fd) {
			if width, _, err := terminal.GetSize(fd); err == nil {
				TermWidth = width
				IsTerminal = true
			}
		}

		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:        "new",
			Aliases:     []string{"n"},
			Usage:       "create md5 file",
			Description: "source output\n\n Arguments:\n   source \tdirectory to checksum\n   output \toutput file",
			Action:      newCommand,
		},
		{
			Name:        "update",
			Aliases:     []string{"u"},
			Usage:       "update existing md5 file with new entries",
			Description: "source target\n\n Arguments:\n   source \tdirectory to checksum\n   target \tmd5 file to update",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "delete, d",
					Usage: "also remove missing checksums from target",
				},
			},
			Action: updateCommand,
		},
		{
			Name:        "verify",
			Aliases:     []string{"v"},
			Usage:       "verify md5 files",
			Description: "path\n\n Arguments:\n   path \tfile to verify (if directory, recursivly find '.md5' files)",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "basic, b",
					Usage: "only check if the files exists",
				},
			},
			Action: verifyCommand,
		},
	}

	app.Run(os.Args)
}
