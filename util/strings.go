package util

import (
	"strings"
)

func TrunkUrlFragment(domList []string) string {
	var builtMatch []string
	var splitStrings [][]string
	for _, dom := range domList {
		parts := strings.Split(dom, ".")
		reverse(&parts)
		splitStrings = append(splitStrings, parts)
	}

	i := 0
main:
	for {
		var proposed string
		for _, slice := range splitStrings {
			if i >= len(slice) {
				break main
			}
			if proposed == "" {
				proposed = slice[i]
			} else if proposed != slice[i] {
				break main
			}
		}
		i++
		builtMatch = append(builtMatch, proposed)
	}
	reverse(&builtMatch)
	return strings.Join(builtMatch, ".")
}

func reverse(input *[]string) {
	for i := 0; i < len(*input)/2; i++ {
		j := len(*input) - i - 1
		(*input)[i], (*input)[j] = (*input)[j], (*input)[i]
	}
}
