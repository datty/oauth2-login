// Most of this code was taken from https://github.com/glestaris/passwduser

package group

import (
	"bufio"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// User represents a user account.
type Group struct {
	Groupname string // user ID
	Password  string // primary group ID
	GID       uint
	Members   []string
}

var groupFilePath = "/etc/group"

// Lookup finds a group by name.
func Lookup(groupName string) (*Group, error) {
	groupFile, err := os.Open(groupFilePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = groupFile.Close()
	}()

	groups, err := parseGroupFilter(groupFile, func(g Group) bool {
		return g.Groupname == groupName
	})
	if err != nil {
		return nil, err
	}

	if len(groups) == 0 {
		return nil, user.UnknownUserError(groupName)
	}

	return &groups[0], nil
}

func parseLine(line string) Group {
	group := Group{}

	// see: man 5 passwd
	//  group_name:password:GID:user_list
	parts := strings.Split(line, ":")
	if len(parts) >= 1 {
		group.Groupname = parts[0]
	}
	if len(parts) >= 3 {
		gid, _ := strconv.ParseUint(parts[2], 10, 0)
		group.GID = uint(gid)
	}
	if len(parts) >= 4 {
		group.Members = strings.Split(parts[3], ",")
	}
	return group
}

func parseGroupFilter(r io.Reader, filter func(Group) bool) ([]Group, error) {
	out := []Group{}

	s := bufio.NewScanner(r)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		p := parseLine(line)
		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}

	return out, nil
}
