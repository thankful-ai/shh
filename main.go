package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

func main() {
	err := run()
	if err != nil {
		switch err.(type) {
		case *emptyArgError:
			usage()
		case *badArgError:
			fmt.Fprintln(os.Stderr, err.Error())
			usage()
		default:
			fmt.Fprintln(os.Stderr, err.Error())
		}
		os.Exit(1)
	}
}

func run() error {
	nonInteractive := flag.Bool("n", false,
		"Non-interactive mode. Fail if shh would prompt for the password")
	shhFileName := flag.String("f", ".shh", "Name of shh file")
	flag.Parse()

	arg, tail := parseArg(flag.Args())
	if arg == "" || arg == "help" {
		return &emptyArgError{}
	}

	// migrateShh file automatically to the latest version.
	err := migrateShh(*shhFileName)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// No need to migrate
	case err != nil:
		return fmt.Errorf("migrate shh: %w", err)
	}

	// Enforce that a .shh file exists for anything for most commands
	switch arg {
	case "init", "gen-keys", "serve", "version": // Do nothing
	default:
		_, err := findFileRecursive(*shhFileName)
		if os.IsNotExist(err) {
			return fmt.Errorf("missing %s, run `shh init`",
				*shhFileName)
		}
		if err != nil {
			return err
		}
	}
	switch arg {
	case "init":
		if tail != nil {
			return fmt.Errorf("unknown args: %v", tail)
		}
		return initShh(*shhFileName)
	case "gen-keys":
		return genKeys(tail)
	case "get":
		return get(*nonInteractive, *shhFileName, tail)
	case "set":
		return set(*shhFileName, tail)
	case "del":
		return del(*shhFileName, tail)
	case "allow":
		return allow(*nonInteractive, *shhFileName, tail)
	case "deny":
		return deny(*shhFileName, tail)
	case "search":
		return search(*shhFileName, tail)
	case "serve":
		return serve(tail)
	case "login":
		return login(tail)
	case "add-user":
		return addUser(*shhFileName, tail)
	case "rm-user":
		return rmUser(*shhFileName, tail)
	case "rename":
		return rename(*shhFileName, tail)
	case "copy":
		return copySecret(*nonInteractive, *shhFileName, tail)
	case "show":
		return show(*shhFileName, tail)
	case "edit":
		return edit(*nonInteractive, *shhFileName, tail)
	case "rotate":
		return rotate(*shhFileName, tail)
	case "version":
		fmt.Println("1.8.0")
		return nil
	default:
		return &badArgError{Arg: arg}
	}
}

// parseArg splits the arguments into a head and tail.
func parseArg(args []string) (string, []string) {
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		return args[0], nil
	default:
		return args[0], args[1:]
	}
}

// genKeys for self in ~/.config/shh.
func genKeys(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath tty"
		execPromises = ""
	)
	pledge(promises, execPromises)

	global, _, err := getConfigPaths()
	if err != nil {
		return err
	}
	_, err = configFromPaths(global, "")
	if err == nil {
		return errors.New("keys exist at ~/.config/shh, run `shh rotate` to change keys")
	}
	if _, err = createUser(global); err != nil {
		return err
	}
	backupReminder(includeConfig)
	return nil
}

// initShh creates your project file ".shh". If the project file already exists
// or if keys have not been generated, initShh reports an error.
//
// This can't easily have unveil applied to it because shh looks recursively up
// directories. Unveil only applies after the .shh file is found, however
// almost no logic exists after that point in this function.
func initShh(filename string) error {
	const (
		promises     = "stdio rpath wpath cpath"
		execPromises = ""
	)
	pledge(promises, execPromises)

	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s exists", filename)
	}
	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return fmt.Errorf("shh from path: %w", err)
	}
	shh.Keys[user.Username] = user.Keys.PublicKeyBlock
	return shh.EncodeToFile()
}

// get a secret value by name.
func get(nonInteractive bool, filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `get $name`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	secretName := args[0]
	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(global, "r")
	if project != "" {
		unveil(project, "r")
	}
	unveil(shh.path, "r")
	unveilBlock()

	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(global, user.Password)
	if err != nil {
		return err
	}
	secret, ok := shh.Secrets[secretName]
	if !ok {
		return fmt.Errorf("%s does not exist", secretName)
	}
	plaintext, err := secret.decrypt(user.Username, keys.PrivateKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	fmt.Print(plaintext)
	return nil
}

// set a secret value.
func set(filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `set $name $val`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return err
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	secretName := args[0]
	plaintext := args[1]

	secret, ok := shh.Secrets[secretName]
	if !ok {
		// If this secret doesn't exist, create it, and give this user
		// access.
		secret = &Secret{
			Users: map[username][]byte{
				user.Username: nil,
			},
		}
	}
	if err = secret.encrypt(plaintext, shh.Keys); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	shh.Secrets[secretName] = secret

	return shh.EncodeToFile()
}

// del deletes a secret for all users. The user does not need to have access to
// the secret to delete it, nor could shh enforce that since one could simply
// delete the secret from the file manually.
func del(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `del $secret`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	secretName := args[0]

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.Secrets[secretName]; !ok {
		return errors.New("secret does not exist")
	}
	delete(shh.Secrets, secretName)

	return shh.EncodeToFile()
}

// allow a user to access a secret. You must have access yourself.
func allow(nonInteractive bool, filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `allow $user $secret`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	usernameToAdd := username(args[0])
	secretName := args[1]

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, prevent further unveils
	unveil(global, "r")
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.Keys[usernameToAdd]; !ok {
		return fmt.Errorf("%s is not a user in the project. "+
			"try `shh add-user %s $PUBKEY`", usernameToAdd,
			usernameToAdd)
	}

	// Decrypt all matching secrets
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(global, user.Password)
	if err != nil {
		return fmt.Errorf("get keys: %w", err)
	}

	secrets := shh.secretsForGlob(secretName)
	if len(secrets) == 0 {
		return errors.New("secret does not exist")
	}
	for i := range secrets {
		secret := secrets[i]

		// Add our user to the secret, then decrypt it using our own
		// key, and re-encrypt it using the new user's key. This
		// re-encrypts for every user, but that's just a side-effect of
		// our simple encrypt API.
		secret.Users[usernameToAdd] = []byte{}
		plaintext, err := secret.decrypt(user.Username,
			keys.PrivateKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		err = secret.encrypt(plaintext, shh.Keys)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
	}
	return shh.EncodeToFile()
}

// deny a user from accessing secrets. Even when removed from access to all
// secrets, their public key will be left untouched in the .shh file and should
// be removed manually with `shh rm-user $user`.
func deny(filename string, args []string) error {
	if len(args) > 2 {
		return errors.New("bad args: expected `deny $user [$secret]`")
	}

	const (
		promises     = "stdio rpath wpath cpath inet"
		execPromises = ""
	)
	pledge(promises, execPromises)

	usernameToDeny := username(args[0])
	var secretName string
	if len(args) == 1 {
		secretName = "*"
	} else {
		secretName = args[1]
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	if _, ok := shh.Keys[usernameToDeny]; !ok {
		return fmt.Errorf("%s is not a user in the project",
			usernameToDeny)
	}

	secrets := shh.secretsForGlob(secretName)
	if len(secrets) == 0 {
		return errors.New("secret does not exist")
	}
	for i := range secrets {
		secret := secrets[i]
		delete(secret.Users, usernameToDeny)
	}
	return shh.EncodeToFile()
}

// search owned secrets for a specific regular expression and output any
// secrets that match.
func search(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `search $regex`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet"
		execPromises = ""
	)
	pledge(promises, execPromises)

	regex, err := regexp.Compile(args[0])
	if err != nil {
		return fmt.Errorf("bad regular expression: %w", err)
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Decrypt all secrets belonging to current user
	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	user.Password, err = requestPasswordFromServer(user.Port, true)
	if err != nil {
		return err
	}
	keys, err := getKeys(global, user.Password)
	if err != nil {
		return fmt.Errorf("get keys: %w", err)
	}

	// Since we're searching the content of secrets, report an error if the
	// user has no access to anything that matches the glob, since that's
	// probably unexpected for the user.
	var hasAccess bool
	for _, s := range shh.Secrets {
		if _, ok := s.Users[user.Username]; ok {
			hasAccess = true
		}
	}
	if !hasAccess {
		return errors.New("no secrets matched, do you have access?")
	}

	// Search each secret and print matches
	for secretName, s := range shh.Secrets {
		if _, ok := s.Users[user.Username]; !ok {
			continue
		}
		plaintext, err := s.decrypt(user.Username, keys.PrivateKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}

		// Output secret names containing the term in separate lines
		// (can then be passed into xargs, etc.)
		if regex.Match([]byte(plaintext)) {
			fmt.Println(secretName)
		}
	}
	return nil
}

// rename secrets.
func rename(filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `rename $old $new`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	oldName, newName := args[0], args[1]
	if oldName == newName {
		return errors.New("names are identical")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.Secrets[oldName]; !ok {
		return errors.New("secret does not exist")
	}
	if _, ok := shh.Secrets[newName]; ok {
		return errors.New("secret already exists by that name")
	}
	shh.Secrets[newName] = shh.Secrets[oldName]
	delete(shh.Secrets, oldName)

	return shh.EncodeToFile()
}

// copySecret for each user that has access to the current secret.
func copySecret(nonInteractive bool, filename string, args []string) error {
	if len(args) != 2 {
		return errors.New("bad args: expected `copy $old $new`")
	}

	const (
		promises     = "stdio rpath wpath cpath tty inet unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	oldName, newName := args[0], args[1]
	if oldName == newName {
		return errors.New("names are identical")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(global, user.Password)
	if err != nil {
		return err
	}

	// Now that we have our files, restrict further access
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, ok := shh.Secrets[oldName]; !ok {
		return errors.New("secret does not exist")
	}
	if _, ok := shh.Secrets[newName]; ok {
		return errors.New("secret already exists by that name")
	}
	shh.Secrets[newName] = shh.Secrets[oldName]

	secret := shh.Secrets[newName]

	// Re-encrypt so as not to reveal that these two secrets are the same
	plaintext, err := secret.decrypt(user.Username, keys.PrivateKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err = secret.encrypt(plaintext, shh.Keys); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return shh.EncodeToFile()
}

// show users and secrets which they can access.
func show(filename string, args []string) error {
	if len(args) > 1 {
		return errors.New("bad args: expected `show [$user]`")
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return showAll(shh)
	}
	return showUser(shh, username(args[0]))
}

// showAll users and sorted secrets alongside a summary.
func showAll(shh *shhV1) error {
	fmt.Println("====== SUMMARY ======")
	if len(shh.Keys) == 1 {
		fmt.Println("1 user")
	} else {
		fmt.Printf("%d users\n", len(shh.Keys))
	}
	if len(shh.Secrets) == 1 {
		fmt.Println("1 secret")
	} else {
		fmt.Printf("%d secrets\n", len(shh.Secrets))
	}
	fmt.Printf("\n")
	fmt.Printf("======= USERS =======")

	// Sort usernames and secrets to give consistent output
	var usernames, secrets []string
	for uname := range shh.Keys {
		usernames = append(usernames, string(uname))
	}
	sort.Strings(usernames)
	for s := range shh.Secrets {
		secrets = append(secrets, s)
	}
	sort.Strings(secrets)

	// Organize secrets by user. This is O(n*m) but isn't that common of an
	// operation. We iterate through secrets in the outer loop because most
	// projects have more secrets than people with access.
	userSecrets := map[username][]string{}
	for _, secretName := range secrets {
		for _, u := range usernames {
			uname := username(u)
			if _, ok := shh.Secrets[secretName].Users[uname]; !ok {
				continue
			}
			userSecrets[uname] = append(userSecrets[uname],
				secretName)
		}
	}
	for _, u := range usernames {
		secrets := userSecrets[username(u)]
		if len(secrets) == 1 {
			fmt.Printf("\n%s (1 secret)\n", u)
		} else {
			fmt.Printf("\n%s (%d secrets)\n", u, len(secrets))
		}
		for _, secret := range secrets {
			fmt.Printf("> %s\n", secret)
		}
	}
	return nil
}

// showUser secrets, sorted.
func showUser(shh *shhV1, username username) error {
	var secrets []string
	for secretName, s := range shh.Secrets {
		if _, ok := s.Users[username]; ok {
			secrets = append(secrets, secretName)
		}
	}
	if len(secrets) == 0 {
		return fmt.Errorf("unknown user: %s", username)
	}
	sort.Strings(secrets)

	for _, secret := range secrets {
		fmt.Printf("%s\n", secret)
	}
	return nil
}

// edit a secret using $EDITOR.
func edit(nonInteractive bool, filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `edit $secret`")
	}
	if os.Getenv("EDITOR") == "" {
		return errors.New("must set $EDITOR")
	}

	const (
		promises     = "stdio rpath wpath cpath tty proc exec inet unveil"
		execPromises = "stdio rpath wpath cpath tty proc exec error"
	)
	pledge(promises, execPromises)

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if nonInteractive {
		user.Password, err = requestPasswordFromServer(user.Port, false)
		if err != nil {
			return err
		}
	} else {
		user.Password, err = requestPassword(user.Port, defaultPasswordPrompt)
		if err != nil {
			return err
		}
	}
	keys, err := getKeys(global, user.Password)
	if err != nil {
		return err
	}

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	unveil(shh.path, "rwc")

	secretName := args[0]

	secret, ok := shh.Secrets[secretName]
	if !ok {
		return fmt.Errorf("%s does not exist", secretName)
	}

	// Expose /tmp for creating a tmp file, a shell to run commands, our
	// configured editor, as well as necessary libraries.
	unveil("/tmp", "rwc")
	unveil("/usr", "r")
	unveil("/var/run", "r")
	unveil("/bin/sh", "x")
	unveil(os.Getenv("EDITOR"), "rx")
	unveilBlock()

	// Create tmp file
	fi, err := ioutil.TempFile("", "shh")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	defer fi.Close()

	// Copy decrypted secret into the temporary file
	plaintext, err := secret.decrypt(user.Username, keys.PrivateKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if _, err = io.Copy(fi, strings.NewReader(plaintext)); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	// Checksum the plaintext, so we can exit early if nothing changed
	// (i.e. don't re-encrypt on saves without changes)
	h := sha1.New()
	if _, err = h.Write([]byte(plaintext)); err != nil {
		return fmt.Errorf("write hash: %w", err)
	}
	origHash := hex.EncodeToString(h.Sum(nil))

	// Open tmp file in our $EDITOR
	cmd := exec.Command("/bin/sh", "-c", "$EDITOR "+fi.Name())
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("cmd: %w", err)
	}
	if err = cmd.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	// At this point we've exited the editor. Check if the contents have
	// changed. If not, we can exit shh early
	newPlaintext, err := ioutil.ReadFile(fi.Name())
	if err != nil {
		return fmt.Errorf("read all: %w", err)
	}
	h = sha1.New()
	if _, err = h.Write(newPlaintext); err != nil {
		return fmt.Errorf("write hash: %w", err)
	}
	newHash := hex.EncodeToString(h.Sum(nil))
	if origHash == newHash {
		return nil
	}

	// If we're here, the content changed. Re-encrypt content for each user
	// with access to the secret.
	if err = secret.encrypt(string(newPlaintext), shh.Keys); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return shh.EncodeToFile()
}

// rotate generates new keys and re-encrypts all secrets using the new keys.
// You should also use this to change your password.
func rotate(filename string, args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath tty"
		execPromises = ""
	)
	pledge(promises, execPromises)

	// Allow changing the password
	oldPass, err := requestPassword(-1, "old password")
	if err != nil {
		return fmt.Errorf("request old password: %w", err)
	}
	newPass, err := requestPasswordAndConfirm("new password")
	if err != nil {
		return fmt.Errorf("request new password: %w", err)
	}

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}

	// Generate new keys (different names). Note we do not use os.TempDir
	// because we'll be renaming the files later, and we can't rename files
	// across partitions (common for Linux)
	tmpDir := filepath.Join(global, "tmp")
	if err = os.Mkdir(tmpDir, 0777); err != nil {
		return fmt.Errorf("make tmp dir: %w", err)
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	keys, err := createKeys(tmpDir, newPass)
	if err != nil {
		return fmt.Errorf("create keys: %w", err)
	}
	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Decrypt all AES secrets for user, re-encrypt with new key
	oldKeys, err := getKeys(global, oldPass)
	if err != nil {
		return err
	}
	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}
	shh.Keys[user.Username] = keys.PublicKeyBlock
	for _, secret := range shh.Secrets {
		if _, ok := secret.Users[user.Username]; !ok {
			continue
		}
		plaintext, err := secret.decrypt(user.Username,
			oldKeys.PrivateKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		if err = secret.encrypt(plaintext, shh.Keys); err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
	}

	// First create backups of our existing keys
	err = copyFile(
		filepath.Join(global, "id_rsa.bak"),
		filepath.Join(global, "id_rsa"),
	)
	if err != nil {
		return fmt.Errorf("back up id_rsa: %w", err)
	}
	err = copyFile(
		filepath.Join(global, "id_rsa.pub.bak"),
		filepath.Join(global, "id_rsa.pub"),
	)
	if err != nil {
		return fmt.Errorf("back up id_rsa.pub: %w", err)
	}

	// Rewrite the project file to use the new public key
	if err = shh.EncodeToFile(); err != nil {
		return fmt.Errorf("encode %s: %w", filename, err)
	}

	// Move new keys on top of current keys in the filesystem
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa"),
		filepath.Join(global, "id_rsa"),
	)
	if err != nil {
		return fmt.Errorf("replace id_rsa: %w", err)
	}
	err = os.Rename(
		filepath.Join(tmpDir, "id_rsa.pub"),
		filepath.Join(global, "id_rsa.pub"),
	)
	if err != nil {
		return fmt.Errorf("replace id_rsa.pub: %w", err)
	}

	// Delete our backed up keys
	err = os.Remove(filepath.Join(global, "id_rsa.bak"))
	if err != nil {
		return fmt.Errorf("delete id_rsa.bak: %w", err)
	}
	err = os.Remove(filepath.Join(global, "id_rsa.pub.bak"))
	if err != nil {
		return fmt.Errorf("delete id_rsa.pub.bak: %w", err)
	}
	backupReminder(skipConfig)
	return nil
}

// addUser to project file.
func addUser(filename string, args []string) error {
	if len(args) != 0 && len(args) != 2 {
		return errors.New("bad args: expected `add-user [$user $pubkey]`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	var u *user
	if len(args) == 0 {
		// Default to self
		global, project, err := getConfigPaths()
		if err != nil {
			return err
		}
		conf, err := configFromPaths(global, project)
		if err != nil {
			return err
		}
		unveil(global, "r")
		u, err = getUser(conf)
		if err != nil {
			return fmt.Errorf("get user: %w", err)
		}
	} else {
		u = &user{Username: username(args[0])}
	}

	// We're done reading files
	unveil(shh.path, "rwc")
	unveilBlock()

	if _, exist := shh.Keys[u.Username]; exist {
		return nil
	}
	if len(args) == 0 {
		shh.Keys[u.Username] = u.Keys.PublicKeyBlock
	} else {
		shh.Keys[u.Username], _ = pem.Decode([]byte(args[1]))
		if shh.Keys[u.Username] == nil {
			return errors.New("bad public key")
		}
	}
	return shh.EncodeToFile()
}

// rmUser from project file.
func rmUser(filename string, args []string) error {
	if len(args) != 1 {
		return errors.New("bad args: expected `rm-user $user`")
	}

	const (
		promises     = "stdio rpath wpath cpath unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	shh, err := shhFromPath(filename)
	if err != nil {
		return err
	}

	unveil(shh.path, "rwc")

	username := username(args[0])
	if _, exist := shh.Keys[username]; !exist {
		return errors.New("user not found")
	}
	for _, s := range shh.Secrets {
		delete(s.Users, username)
	}
	delete(shh.Keys, username)
	return shh.EncodeToFile()
}

// serve maintains the password in memory for an hour. serve cannot be pledged
// because mlock is not allowed, but we are able to unveil.
func serve(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	unveil(global, "r")
	unveilBlock()

	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	const tickTime = time.Hour
	var mu sync.Mutex

	// Clear secrets when exiting
	memguard.CatchInterrupt()
	defer memguard.Purge()

	var pwEnclave *memguard.Enclave
	resetTicker := make(chan struct{})
	ticker := time.NewTicker(tickTime)
	go func() {
		for {
			select {
			case <-resetTicker:
				ticker.Stop()
				ticker = time.NewTicker(tickTime)
			case <-ticker.C:
				mu.Lock()
				pwEnclave = nil
				mu.Unlock()
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/reset-timer" {
			resetTicker <- struct{}{}
		}
		if r.Method == "GET" {
			if pwEnclave == nil {
				w.WriteHeader(http.StatusOK)
				return
			}
			b, err := pwEnclave.Open()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer b.Destroy()
			_, _ = w.Write(b.Bytes())
			return
		}
		byt, err := ioutil.ReadAll(r.Body)
		if len(byt) == 0 && err == nil {
			err = errors.New("empty body")
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		pwEnclave = memguard.NewEnclave(byt)
		w.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(fmt.Sprint(":", user.Port), mux)
}

// login to the server, caching the password in memory for 1 hour.
func login(args []string) error {
	if len(args) != 0 {
		return errors.New("bad args: expected none")
	}

	const (
		promises     = "stdio rpath wpath cpath inet proc exec tty unveil"
		execPromises = ""
	)
	pledge(promises, execPromises)

	global, project, err := getConfigPaths()
	if err != nil {
		return err
	}
	conf, err := configFromPaths(global, project)
	if err != nil {
		return err
	}
	unveil(global, "r")

	user, err := getUser(conf)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Ensure the server is available
	url := fmt.Sprint("http://127.0.0.1:", user.Port)
	if err = pingServer(url); err != nil {
		return err
	}

	// Attempt to use cached password before asking again
	user.Password, err = requestPasswordFromServer(user.Port, true)
	if err == nil {
		return nil
	}

	user.Password, err = requestPassword(-1, defaultPasswordPrompt)
	if err != nil {
		return fmt.Errorf("request password: %w", err)
	}

	// Verify the password before continuing
	if _, err = getKeys(global, user.Password); err != nil {
		return err
	}
	buf := bytes.NewBuffer(user.Password)
	resp, err := http.Post(url, "plaintext", buf)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	return nil
}

func copyFile(dst, src string) error {
	srcFi, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFi.Close()

	// Create the destination file with the same permissions as the source
	// file
	srcStat, err := srcFi.Stat()
	if err != nil {
		return err
	}
	dstFi, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, srcStat.Mode())
	if err != nil {
		return err
	}
	defer dstFi.Close()

	if _, err = io.Copy(dstFi, srcFi); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

func usage() {
	fmt.Println(`usage:

	shh [flags] [command]

global commands:
	init                    initialize store or add self to existing store
	get $name               get secret
	set $name $val          set secret
	del $name               delete a secret
	copy $old $new          copy a secret, maintaining the same team access
	rename $old $new        rename a secret
	allow $user $secret     allow user access to a secret
	deny $user $secret      deny user access to a secret
	add-user $user $pubkey  add user to project given their public key
	rm-user $user           remove user from project
	search $regex           list all secrets containing the regex
	show [$user]            show user's allowed and denied keys
	edit                    edit a secret using $EDITOR
	rotate                  rotate key
	serve                   start server to maintain password in memory
	gen-keys                generate global keys and configuration files
	login                   login to server to maintain password in memory
	version                 version information
	help                    usage info

flags:
	-n                      Non-interactive mode. Fail if shh would prompt for the password
	-f                      shh filename. Defaults to .shh`)
}

type configOpt bool

const (
	includeConfig configOpt = true
	skipConfig    configOpt = false
)

func backupReminder(withConfig configOpt) {
	if withConfig {
		fmt.Println("> generated ~/.config/shh/config")
	}
	fmt.Println("> generated ~/.config/shh/id_rsa")
	fmt.Println("> generated ~/.config/shh/id_rsa.pub")
	fmt.Println(">")
	fmt.Println("> be sure to back up your ~/.config/shh/id_rsa and remember your password, or")
	fmt.Println("> you may lose access to your secrets!")
}
