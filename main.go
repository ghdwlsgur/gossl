package main

import "github.com/ghdwlsgur/cert-check/cmd"

// import "github.com/ghdwlsgur/cert-check/cmd"

func main() {
	cmd.Execute("1.0")

	// var files []string
	// fileInfo, err := os.ReadDir("./")
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// for _, f := range fileInfo {
	// 	if !f.Type().IsDir() {
	// 		s := strings.Split(f.Name(), ".")
	// 		extension := s[len(s)-1]
	// 		if extension == "pem" || extension == "crt" || extension == "key" {
	// 			files = append(files, f.Name())
	// 		}
	// 	}
	// }

	// // key pem crt
	// fmt.Println(files)

}
