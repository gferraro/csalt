package userapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v2"
)

const (
	userConfig    = "user.yaml"
	tokenFileName = ".token"
)

type Config struct {
	ServerURL string `yaml:"server-url" json:"serverURL"`
	UserName  string `yaml:"user-name" json:"username"`
	Token     string
	filePath  string
}

func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir
}

func ParseOrCreateConfig() {
	homeDir := userHomeDir()
	filePath := path.Join(homeDir, userConfig)

	if exists, err := afero.Exists(Fs, filePath); err != nil {
		return nil, err
	} else if !exists {
		return nil, errors.New("user config is missing")
	}

	conf := &Config{filePath: filePath}
	if err := conf.read(); err != nil {
		return nil, err
	}
}

func NewConfig() (*Config, error) {
	homeDir := userHomeDir()
	filePath := path.Join(homeDir, userConfig)

	if exists, err := afero.Exists(Fs, filePath); err != nil {
		return nil, err
	} else if !exists {
		return nil, errors.New("user config is missing")
	}

	conf := &Config{filePath: filePath}
	if err := conf.read(); err != nil {
		return nil, err
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	token, err := LoadToken()
	if err != nil {
		fmt.Errorf("error loading token%v", err)
	}
	conf.Token = token

	return conf, nil
}

func (c *Config) read() error {
	buf, err := afero.ReadFile(Fs, c.filePath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, c)
}

//Validate checks supplied Config contains the required data
func (conf *Config) Validate() error {
	if conf.ServerURL == "" {
		return errors.New("server-url missing")
	}

	if conf.UserName == "" {
		return errors.New("user-name is missing")
	}
	return nil
}

const (
	lockRetryDelay = 678 * time.Millisecond
	lockTimeout    = 5 * time.Second
)

// LoadPrivateConfig acquires a readlock and reads private config
func LoadToken() (string, error) {
	tokenPath := path.Join(userHomeDir(), tokenFileName)

	lockSafeConfig := NewLockSafeConfig(tokenPath)
	return lockSafeConfig.Read()
}

func SaveToken(token string) error {
	tokenPath := path.Join(userHomeDir(), tokenFileName)
	lockSafeConfig := NewLockSafeConfig(tokenPath)
	_, err := lockSafeConfig.ExLock()
	if err != nil {
		return err
	}
	return lockSafeConfig.Write(token)
}

type LockSafeConfig struct {
	fileLock *flock.Flock
	filename string
	token    string
}

func NewLockSafeConfig(filename string) *LockSafeConfig {
	lockFile := filename + ".lock"
	return &LockSafeConfig{
		filename: filename,
		fileLock: flock.New(lockFile),
	}
}

func (lockSafeConfig *LockSafeConfig) Unlock() {
	lockSafeConfig.fileLock.Unlock()
}

// ExLock acquires an exclusive lock on confPassword
func (lockSafeConfig *LockSafeConfig) ExLock() (bool, error) {
	lockCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	locked, err := lockSafeConfig.fileLock.TryLockContext(lockCtx, lockRetryDelay)
	return locked, err
}

// readLock  acquires a read lock on the supplied Flock struct
func readLock(fileLock *flock.Flock) (bool, error) {
	lockCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	locked, err := fileLock.TryRLockContext(lockCtx, lockRetryDelay)
	return locked, err
}

// ReadPassword acquires a readlock and reads the config
func (lockSafeConfig *LockSafeConfig) Read() (string, error) {
	locked := lockSafeConfig.fileLock.Locked()
	if locked == false {
		locked, err := readLock(lockSafeConfig.fileLock)
		if locked == false || err != nil {
			return "", err
		}
		defer lockSafeConfig.Unlock()
	}

	buf, err := afero.ReadFile(Fs, lockSafeConfig.filename)
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}

	return string(buf), nil
}

// WritePassword checks the file is locked and writes the password
func (lockSafeConfig *LockSafeConfig) Write(token string) error {

	if lockSafeConfig.fileLock.Locked() {
		err := afero.WriteFile(Fs, lockSafeConfig.filename, []byte(token), 0600)
		return err
	} else {
		return fmt.Errorf("file is not locked %v", lockSafeConfig.filename)
	}
}

var Fs = afero.NewOsFs()
