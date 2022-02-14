package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

// MakeDir just make a folder
func MakeDir(folder string) {
	os.MkdirAll(folder, 0750)
}

// GetCurrentDay get current day
func GetCurrentDay() string {
	currentTime := time.Now()
	return fmt.Sprintf("%v", currentTime.Format("2006-01-02_3:4:5"))
}

// ReadingLines Reading file and return content as []string
func ReadingLines(filename string) []string {
	var result []string
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := scanner.Text()
		if val == "" {
			continue
		}
		result = append(result, val)
	}

	if err := scanner.Err(); err != nil {
		return result
	}
	return result
}

// GetFileNames get all file name with extension
func GetFileNames(dir string, ext string) []string {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}

	var files []string
	filepath.Walk(dir, func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() {
			if strings.HasSuffix(f.Name(), ext) {
				filename, _ := filepath.Abs(path)
				files = append(files, filename)
			}
		}
		return nil
	})
	return files
}

// FileExists check if file is exist or not
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// FolderExists check if file is exist or not
func FolderExists(foldername string) bool {
	//foldername = NormalizePath(foldername)
	if _, err := os.Stat(foldername); os.IsNotExist(err) {
		return false
	}
	return true
}

//func RandomStr(randSource *rand.Rand, letterBytes string, n int) string {
//	const (
//		letterIdxBits = 6                    // 6 bits to represent a letter index
//		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
//		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
//		//letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
//	)
//	randBytes := make([]byte, n)
//	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
//		if remain == 0 {
//			cache, remain = randSource.Int63(), letterIdxMax
//		}
//		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
//			randBytes[i] = letterBytes[idx]
//			i--
//		}
//		cache >>= letterIdxBits
//		remain--
//	}
//	return string(randBytes)
//}

const (
	chars    = "0123456789abcdef" //ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_
	charsLen = len(chars)
	mask     = 1<<6 - 1
)

var rng = rand.NewSource(time.Now().UnixNano())

// RandStr 返回指定长度的随机字符串
func RandStr(ln int) string {
	/* chars 38个字符
	 * rng.Int63() 每次产出64bit的随机数,每次我们使用6bit(2^6=64) 可以使用10次
	 */
	buf := make([]byte, ln)
	for idx, cache, remain := ln-1, rng.Int63(), 10; idx >= 0; {
		if remain == 0 {
			cache, remain = rng.Int63(), 10
		}
		buf[idx] = chars[int(cache&mask)%charsLen]
		cache >>= 6
		remain--
		idx--
	}
	return *(*string)(unsafe.Pointer(&buf))
}
