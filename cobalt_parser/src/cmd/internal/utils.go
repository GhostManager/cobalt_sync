package internal

// @its_a_feature_ 8/30/2023
import (
	"fmt"
	"os"
	"strings"
)

func StringInSlice(value string, searchSlice []string) bool {
	for i := 0; i < len(searchSlice); i++ {
		if searchSlice[i] == value {
			return true
		}
	}
	return false
}

func getYearFromPath(path string) string {
	pathPieces := strings.Split(path, string(os.PathSeparator))
	if len(pathPieces) < 3 {
		fmt.Printf("Can't find year\n")
		return ""
	}
	dateString := pathPieces[len(pathPieces)-3]
	return "20" + dateString[:2]
}
