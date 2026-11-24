// Package cliflag holds the flag parsing the segurata subcommands share.
package cliflag

import "flag"

// Parse parses flags wherever they appear, so `done <id> --note x` works as well as
// `done --note x <id>`, and returns the positional arguments in order.
func Parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
