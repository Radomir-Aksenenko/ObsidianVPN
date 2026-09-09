package tun

func splitFields(s string) []string {
	var res []string
	var cur []rune
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if len(cur) > 0 {
				res = append(res, string(cur))
				cur = cur[:0]
			}
		} else {
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		res = append(res, string(cur))
	}
	return res
}

func splitLines(s string) []string {
	var lines []string
	var cur []rune
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, string(cur))
			cur = cur[:0]
		} else if r != '\r' {
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return lines
}
