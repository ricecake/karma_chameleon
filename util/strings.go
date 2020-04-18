package util

import (
	"strings"
)

func TrunkUrlFragment(domList []string) string {
	var builtMatch []string
	var splitStrings [][]string
	for _, dom := range domList {
		parts := strings.Split(dom, ".")
		Reverse(&parts)
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
	Reverse(&builtMatch)
	return strings.Join(builtMatch, ".")
}

func Reverse(input *[]string) {
	for i := 0; i < len(*input)/2; i++ {
		j := len(*input) - i - 1
		(*input)[i], (*input)[j] = (*input)[j], (*input)[i]
	}
}

func Contains(container, things []string) bool {
	for _, thing := range things {
		if _, found := IndexOf(thing, container); !found {
			return false
		}
	}
	return true
}

func IndexOf(it string, list []string) (int, bool) {
	for index, value := range list {
		if value == it {
			return index, true
		}
	}
	return 0, false
}
