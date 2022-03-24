package core

import (
	"github.com/r0ckysec/go-security/log"
	"github.com/thinkeridea/go-extend/exstrings"
	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
	"poc-go/lib/utils"
	"strings"
)

type Poc struct {
	Name   string             `yaml:"name"`
	Set    yaml.MapSlice      `yaml:"set"`
	Rules  []*Rule            `yaml:"rules"`
	Groups map[string][]*Rule `yaml:"groups"`
	Detail Detail             `yaml:"detail"`
}

type Rule struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Paths           []string          `yaml:"paths"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadSinglePoc(fileName string) (*Poc, error) {
	return loadPoc(fileName)
}

func LoadMultiPoc(fileName string) []*Poc {
	fileName = exstrings.Replace(fileName, "\\", "/", -1)
	var pocs []*Poc
	for _, f := range SelectPoc(fileName) {
		if p, err := loadPoc(f); err == nil {
			pocs = append(pocs, p)
		}
	}
	return pocs
}

func loadPoc(fileName string) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error(err, fileName)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		log.Error(err, fileName)
		return nil, err
	}
	return p, err
}

func SelectPoc(fileName string) []string {
	return funk.UniqString(singlePoc(fileName))
}

func singlePoc(fileName string) []string {
	var foundFiles []string
	if strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".yaml") {
		if utils.FileExists(fileName) {
			foundFiles = append(foundFiles, fileName)
		}
	}
	// get more poc
	if strings.Contains(fileName, "*") && strings.Contains(fileName, "/") {
		asbPath, _ := filepath.Abs(fileName)
		//baseSelect := filepath.Base(fileName)
		glob, err := filepath.Glob(asbPath)
		if err != nil {
			return foundFiles
		}
		foundFiles = append(foundFiles, utils.GetFileExt(glob, "yml")...)
		foundFiles = append(foundFiles, utils.GetFileExt(glob, "yaml")...)
	}
	return foundFiles
}
