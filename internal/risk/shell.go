package risk

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

const maxShellNesting = 6

var shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

type shellToken struct {
	word      string
	separator bool
}

type shellCommand struct {
	words     []string
	connector string
}

type shellProgram struct {
	commands      []shellCommand
	substitutions []string
	malformed     bool
}

func collectShellSignals(action models.Action, collector *signalCollector) {
	commandAnalyzed := false
	if command, ok := firstValue(action.Arguments, "command", "cmd", "script"); ok {
		switch typed := command.(type) {
		case string:
			analyzeShellText(typed, collector, 0)
			commandAnalyzed = true
		case []string:
			analyzeShellCommands([]shellCommand{{words: append([]string(nil), typed...)}}, collector, 0)
			commandAnalyzed = true
		case []any:
			if words, ok := stringValues(typed); ok {
				analyzeShellCommands([]shellCommand{{words: words}}, collector, 0)
				commandAnalyzed = true
			} else {
				collector.add("shell-parse-ambiguity", 45, "Command array contains a non-text argument")
			}
		default:
			collector.add("shell-parse-ambiguity", 45, "Shell command could not be interpreted safely")
		}
	}

	if !commandAnalyzed {
		executable := firstString(action.Arguments, "executable", "program", "binary")
		if executable != "" {
			words := []string{executable}
			if rawArgs, ok := firstValue(action.Arguments, "args", "argv", "arguments"); ok {
				switch typed := rawArgs.(type) {
				case []string:
					words = append(words, typed...)
				case []any:
					if values, ok := stringValues(typed); ok {
						words = append(words, values...)
					} else {
						collector.add("shell-parse-ambiguity", 45, "Executable arguments could not be interpreted safely")
					}
				}
			}
			analyzeShellCommands([]shellCommand{{words: words}}, collector, 0)
		}
	}

	collectShellEnvironmentSignals(action.Arguments, collector)
	collectShellStdinSignals(action.Arguments, collector)
}

func collectShellEnvironmentSignals(arguments map[string]any, collector *signalCollector) {
	raw, exists := arguments["environment_changes"]
	if !exists {
		return
	}
	changes, ok := raw.([]any)
	if !ok {
		collector.add("shell-parse-ambiguity", 45, "Environment changes could not be interpreted safely")
		return
	}
	if len(changes) > 0 {
		collector.add("process-environment-modification", 20, "Process environment variables are changed")
	}
	for _, rawChange := range changes {
		change, ok := rawChange.(map[string]any)
		if !ok {
			collector.add("shell-parse-ambiguity", 45, "Environment change entry could not be interpreted safely")
			continue
		}
		name, ok := change["name"].(string)
		if !ok || strings.TrimSpace(name) == "" {
			collector.add("shell-parse-ambiguity", 45, "Environment change is missing a variable name")
			continue
		}
		switch strings.ToUpper(name) {
		case "PATH", "PATHEXT":
			collector.add("process-search-path-modification", 45, "Process search path is modified")
		case "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND", "PS4",
			"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
			"PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "RUBYOPT", "PERL5OPT", "COMSPEC":
			collector.add("execution-environment-injection", 70, "Process environment can inject code or alter interpreter startup")
		}
	}
}

func collectShellStdinSignals(arguments map[string]any, collector *signalCollector) {
	rawBytes, exists := arguments["stdin_bytes"]
	if !exists || numericZero(rawBytes) {
		return
	}
	collector.add("process-stdin", 10, "Process receives caller-controlled standard input")
	executable := executableName(firstString(arguments, "executable", "program", "binary"))
	if isCommandConsumer(executable) {
		collector.add("opaque-interpreter-input", 70, "A command interpreter receives opaque standard input")
	}
}

func numericZero(value any) bool {
	switch typed := value.(type) {
	case int:
		return typed == 0
	case int64:
		return typed == 0
	case float64:
		return typed == 0
	case json.Number:
		return typed.String() == "0"
	default:
		return false
	}
}

func analyzeShellText(command string, collector *signalCollector, depth int) {
	if strings.TrimSpace(command) == "" {
		return
	}
	if depth >= maxShellNesting {
		collector.add("shell-nesting-limit", 55, "Shell nesting exceeded the safe analysis depth")
		return
	}
	program := parseShell(command)
	if program.malformed {
		collector.add("shell-parse-ambiguity", 45, "Shell syntax is incomplete or ambiguous")
	}
	analyzeShellCommands(program.commands, collector, depth)
	for _, substitution := range program.substitutions {
		analyzeShellText(substitution, collector, depth+1)
	}
}

func analyzeShellCommands(commands []shellCommand, collector *signalCollector, depth int) {
	for index, command := range commands {
		if payload, ok := shellWrapperPayload(command.words); ok {
			analyzeShellText(payload, collector, depth+1)
		}
		executable, args, privileged := resolveShellExecutable(command.words)
		if privileged {
			collector.add("privilege-escalation", 45, "Privilege escalation command detected")
		}
		if executable == "" {
			continue
		}

		switch executable {
		case "rm":
			if hasAnyFlag(args, "-r", "-R", "--recursive", "-recurse") || hasCombinedShortFlag(args, 'r') {
				collector.add("recursive-deletion", 90, "Recursive deletion command detected")
			} else {
				collector.add("file-deletion", 55, "File deletion command detected")
			}
		case "rmdir", "rd":
			if hasAnyFlagFold(args, "/s", "-recurse") {
				collector.add("recursive-deletion", 90, "Recursive directory deletion command detected")
			} else {
				collector.add("file-deletion", 55, "Directory deletion command detected")
			}
		case "del", "erase", "remove-item", "ri":
			if hasAnyFlagFold(args, "/s", "-recurse") || hasEnabledPowerShellSwitch(args, "-recurse") {
				collector.add("recursive-deletion", 90, "Recursive deletion command detected")
			} else {
				collector.add("file-deletion", 55, "File deletion command detected")
			}
		case "find":
			if hasArgumentFold(args, "-delete") {
				collector.add("recursive-deletion", 90, "Recursive find deletion detected")
			}
		case "shred":
			collector.add("file-deletion", 65, "Secure file deletion command detected")
		case "chmod":
			if unsafeMode(args) {
				collector.add("unsafe-permissions", 45, "World-writable permission change detected")
			}
		case "icacls":
			if unsafeWindowsACL(args) {
				collector.add("unsafe-permissions", 45, "Broad Windows permission grant detected")
			}
		case "docker":
			if startsWithFold(args, "system", "prune") || startsWithFold(args, "volume", "prune") {
				collector.add("container-prune", 65, "Container data cleanup requested")
			}
		case "kubectl":
			if hasArgumentFold(args, "delete") {
				collector.add("cluster-deletion", 75, "Kubernetes resource deletion requested")
			}
		case "helm":
			if hasArgumentFold(args, "uninstall") {
				collector.add("cluster-deletion", 65, "Kubernetes release deletion requested")
			}
		case "pg_dump", "pg_dumpall", "mysqldump", "mongodump":
			collector.add("database-dump", 85, "Database export command detected")
		case "env", "printenv", "get-childitem", "gci":
			if executable != "get-childitem" && executable != "gci" || containsEnvironmentTarget(args) {
				collector.add("environment-enumeration", 25, "Environment enumeration can expose secrets")
			}
		case "set":
			if len(args) == 0 {
				collector.add("environment-enumeration", 25, "Environment enumeration can expose secrets")
			}
		case "eval", "iex", "invoke-expression":
			collector.add("dynamic-code-execution", 55, "Dynamic command evaluation detected")
		case "powershell", "pwsh":
			if hasPowerShellEncodedCommand(args) {
				collector.add("encoded-script-execution", 85, "Encoded PowerShell execution detected")
			}
		}

		if payload, ok := nestedShellPayload(executable, args); ok {
			analyzeShellText(payload, collector, depth+1)
		}
		if isDynamicRuntime(executable, args) {
			collector.add("dynamic-code-execution", 55, "Inline code execution detected")
		}
		if request, ok := shellHTTPRequest(executable, args); ok {
			collectHTTPArguments(request, collector)
		}
		for _, uploadPath := range shellUploadPaths(executable, args) {
			collector.add("outbound-file-transfer", 40, "Command uploads a local file to a network destination")
			for _, signal := range pathSignals(lower(strings.TrimPrefix(uploadPath, "@"))) {
				collector.add(signal.Name, signal.Score, signal.Description)
			}
		}

		if index > 0 && (command.connector == "|" || command.connector == "|&") {
			if isCommandConsumer(executable) && pipelineContainsDownloader(commands, index) {
				collector.add("remote-script-execution", 85, "Remote content reaches a command interpreter through a pipeline")
			}
			previousExecutable, _, _ := resolveShellExecutable(commands[index-1].words)
			if isDecoder(previousExecutable, commands[index-1].words) && isCommandConsumer(executable) {
				collector.add("encoded-script-execution", 85, "Decoded content is piped directly to a command interpreter")
			}
		}
		if index > 0 && (command.connector == "&&" || command.connector == ";") {
			previousExecutable, previousArgs, _ := resolveShellExecutable(commands[index-1].words)
			output := downloaderOutput(previousExecutable, previousArgs)
			if output != "" && ((isCommandConsumer(executable) && containsExactArgument(args, output)) || sameExecutablePath(executable, output)) {
				collector.add("remote-script-execution", 85, "Downloaded content is executed by a command interpreter")
			}
		}
	}
}

func shellWrapperPayload(words []string) (string, bool) {
	index := 0
	for index < len(words) && shellAssignment.MatchString(words[index]) {
		index++
	}
	if index >= len(words) || executableName(words[index]) != "su" {
		return "", false
	}
	return valueAfterFlag(words[index+1:], "-c", "--command")
}

func parseShell(input string) shellProgram {
	tokens, substitutions, malformed := lexShell(input)
	program := shellProgram{substitutions: substitutions, malformed: malformed}
	var words []string
	connector := ""
	flush := func() {
		if len(words) == 0 {
			return
		}
		program.commands = append(program.commands, shellCommand{words: words, connector: connector})
		words = nil
	}
	for _, token := range tokens {
		if token.separator {
			flush()
			connector = token.word
			continue
		}
		words = append(words, token.word)
	}
	flush()
	return program
}

func lexShell(input string) ([]shellToken, []string, bool) {
	var tokens []shellToken
	var substitutions []string
	var current strings.Builder
	quote := byte(0)
	malformed := false
	wordStarted := false
	flush := func() {
		if wordStarted {
			tokens = append(tokens, shellToken{word: current.String()})
			current.Reset()
			wordStarted = false
		}
	}

	for index := 0; index < len(input); index++ {
		character := input[index]
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			} else {
				current.WriteByte(character)
			}
			wordStarted = true
			continue
		}
		if quote == '"' {
			if character == '"' {
				quote = 0
				wordStarted = true
				continue
			}
			if character == '\\' && index+1 < len(input) {
				index++
				current.WriteByte(input[index])
				wordStarted = true
				continue
			}
			if character == '$' && index+1 < len(input) && input[index+1] == '(' {
				content, end, ok := consumeDollarSubstitution(input, index)
				if !ok {
					malformed = true
					current.WriteString(input[index:])
					break
				}
				substitutions = append(substitutions, content)
				current.WriteString(input[index : end+1])
				wordStarted = true
				index = end
				continue
			}
			current.WriteByte(character)
			wordStarted = true
			continue
		}

		switch {
		case character == '\'' || character == '"':
			quote = character
			wordStarted = true
		case character == '\\':
			wordStarted = true
			if index+1 >= len(input) {
				malformed = true
				continue
			}
			index++
			current.WriteByte(input[index])
		case character == '$' && index+1 < len(input) && input[index+1] == '(':
			content, end, ok := consumeDollarSubstitution(input, index)
			if !ok {
				malformed = true
				current.WriteString(input[index:])
				index = len(input)
				continue
			}
			substitutions = append(substitutions, content)
			current.WriteString(input[index : end+1])
			wordStarted = true
			index = end
		case character == '`':
			content, end, ok := consumeBacktickSubstitution(input, index)
			if !ok {
				malformed = true
				current.WriteString(input[index:])
				index = len(input)
				continue
			}
			substitutions = append(substitutions, content)
			current.WriteString(input[index : end+1])
			wordStarted = true
			index = end
		case character == '#':
			if !wordStarted {
				for index < len(input) && input[index] != '\n' {
					index++
				}
				flush()
				if index < len(input) {
					tokens = append(tokens, shellToken{word: ";", separator: true})
				}
			} else {
				current.WriteByte(character)
			}
		case character == ' ' || character == '\t' || character == '\r':
			flush()
		case character == '\n':
			flush()
			tokens = append(tokens, shellToken{word: ";", separator: true})
		case strings.ContainsRune(";|&()", rune(character)):
			flush()
			operator := string(character)
			if index+1 < len(input) {
				pair := input[index : index+2]
				if pair == "&&" || pair == "||" || pair == "|&" {
					operator = pair
					index++
				}
			}
			tokens = append(tokens, shellToken{word: operator, separator: true})
		case character == '<' || character == '>':
			flush()
			operator := string(character)
			if index+1 < len(input) && input[index+1] == character {
				operator += string(character)
				index++
			}
			tokens = append(tokens, shellToken{word: operator})
		default:
			current.WriteByte(character)
			wordStarted = true
		}
	}
	if quote != 0 {
		malformed = true
	}
	flush()
	return tokens, substitutions, malformed
}

func consumeDollarSubstitution(input string, start int) (string, int, bool) {
	depth := 1
	quote := byte(0)
	for index := start + 2; index < len(input); index++ {
		character := input[index]
		if quote != 0 {
			if character == '\\' && quote == '"' {
				index++
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == '\\' {
			index++
			continue
		}
		if character == '(' {
			depth++
		}
		if character == ')' {
			depth--
			if depth == 0 {
				return input[start+2 : index], index, true
			}
		}
	}
	return "", len(input), false
}

func consumeBacktickSubstitution(input string, start int) (string, int, bool) {
	for index := start + 1; index < len(input); index++ {
		if input[index] == '\\' {
			index++
			continue
		}
		if input[index] == '`' {
			return input[start+1 : index], index, true
		}
	}
	return "", len(input), false
}

func resolveShellExecutable(words []string) (string, []string, bool) {
	index := 0
	for index < len(words) && shellAssignment.MatchString(words[index]) {
		index++
	}
	privileged := false
	for index < len(words) {
		executable := executableName(words[index])
		index++
		switch executable {
		case "sudo", "doas":
			privileged = true
			index = skipWrapperFlags(words, index, map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "--user": true, "--group": true})
		case "su":
			privileged = true
			index = skipWrapperFlags(words, index, map[string]bool{"-c": true, "--command": true, "-s": true, "--shell": true})
		case "env":
			for index < len(words) && (strings.HasPrefix(words[index], "-") || shellAssignment.MatchString(words[index])) {
				index++
			}
		case "command", "builtin", "nohup":
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				index++
			}
		case "time":
			for index < len(words) && strings.HasPrefix(words[index], "-") {
				index++
			}
		default:
			return executable, words[index:], privileged
		}
	}
	return "", nil, privileged
}

func skipWrapperFlags(words []string, index int, flagsWithValue map[string]bool) int {
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		flag := words[index]
		index++
		if flagsWithValue[flag] && index < len(words) {
			index++
		}
	}
	return index
}

func executableName(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	value = filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	value = strings.ToLower(value)
	for _, suffix := range []string{".exe", ".cmd", ".bat", ".com"} {
		value = strings.TrimSuffix(value, suffix)
	}
	return value
}

func nestedShellPayload(executable string, args []string) (string, bool) {
	switch executable {
	case "sh", "bash", "zsh", "dash", "ksh":
		for index, argument := range args {
			if len(argument) > 2 && argument[0] == '-' && argument[1] != '-' && strings.ContainsRune(argument[1:], 'c') && index+1 < len(args) {
				return args[index+1], true
			}
		}
		return valueAfterFlag(args, "-c", "--command")
	case "powershell", "pwsh":
		return valueAfterFlagFold(args, "-command", "-c")
	case "cmd":
		return valueAfterFlagFold(args, "/c", "/k")
	case "eval", "iex", "invoke-expression":
		if len(args) > 0 {
			return strings.Join(args, " "), true
		}
	}
	return "", false
}

func pipelineContainsDownloader(commands []shellCommand, consumerIndex int) bool {
	for index := consumerIndex - 1; index >= 0; index-- {
		if commands[index+1].connector != "|" && commands[index+1].connector != "|&" {
			return false
		}
		executable, _, _ := resolveShellExecutable(commands[index].words)
		if isDownloader(executable) {
			return true
		}
	}
	return false
}

func isDynamicRuntime(executable string, args []string) bool {
	switch executable {
	case "python", "python3", "python2", "node", "ruby", "perl", "php":
		_, ok := valueAfterFlag(args, "-c", "-e", "--eval")
		return ok
	}
	return false
}

func isDownloader(executable string) bool {
	switch executable {
	case "curl", "wget", "fetch", "invoke-webrequest", "invoke-restmethod", "iwr", "irm":
		return true
	default:
		return false
	}
}

func isCommandConsumer(executable string) bool {
	switch executable {
	case "sh", "bash", "zsh", "dash", "ksh", "powershell", "pwsh", "cmd", "iex", "invoke-expression", "python", "python3", "node", "ruby", "perl":
		return true
	default:
		return false
	}
}

func isDecoder(executable string, words []string) bool {
	if executable == "base64" {
		return hasArgumentFold(words, "-d") || hasArgumentFold(words, "--decode")
	}
	if executable == "certutil" {
		return hasArgumentFold(words, "-decode")
	}
	return false
}

func downloaderOutput(executable string, args []string) string {
	switch executable {
	case "curl":
		if value, ok := valueAfterFlag(args, "-o", "--output"); ok {
			return value
		}
	case "wget":
		if value, ok := valueAfterFlag(args, "-O", "--output-document"); ok {
			return value
		}
	case "invoke-webrequest", "invoke-restmethod", "iwr", "irm":
		if value, ok := valueAfterFlagFold(args, "-outfile"); ok {
			return value
		}
	}
	if value, ok := valueAfterFlag(args, ">", "1>"); ok {
		return value
	}
	return ""
}

func shellHTTPRequest(executable string, args []string) (map[string]any, bool) {
	request := map[string]any{}
	var headers []string
	var body []string
	switch executable {
	case "curl":
		for index := 0; index < len(args); index++ {
			argument := args[index]
			switch {
			case argument == "--url" && index+1 < len(args):
				index++
				request["url"] = args[index]
			case strings.HasPrefix(argument, "--url="):
				request["url"] = strings.TrimPrefix(argument, "--url=")
			case (argument == "-H" || argument == "--header") && index+1 < len(args):
				index++
				headers = append(headers, args[index])
			case strings.HasPrefix(argument, "--header="):
				headers = append(headers, strings.TrimPrefix(argument, "--header="))
			case strings.HasPrefix(argument, "-H") && len(argument) > 2:
				headers = append(headers, argument[2:])
			case (argument == "-d" || argument == "--data" || argument == "--data-raw" || argument == "--data-binary" || argument == "--data-urlencode" || argument == "-F" || argument == "--form") && index+1 < len(args):
				index++
				body = append(body, args[index])
			case hasAnyPrefix(argument, "--data=", "--data-raw=", "--data-binary=", "--data-urlencode=", "--form="):
				_, value, _ := strings.Cut(argument, "=")
				body = append(body, value)
			case (argument == "-X" || argument == "--request") && index+1 < len(args):
				index++
				request["method"] = args[index]
			case strings.HasPrefix(argument, "--request="):
				request["method"] = strings.TrimPrefix(argument, "--request=")
			case strings.HasPrefix(argument, "-X") && len(argument) > 2:
				request["method"] = argument[2:]
			case (argument == "-u" || argument == "--user" || argument == "--oauth2-bearer") && index+1 < len(args):
				index++
				headers = append(headers, "Authorization: [credential]")
			case hasAnyPrefix(argument, "--user=", "--oauth2-bearer="):
				headers = append(headers, "Authorization: [credential]")
			case strings.HasPrefix(argument, "-u") && len(argument) > 2:
				headers = append(headers, "Authorization: [credential]")
			case argument == "-k" || argument == "--insecure":
				request["insecure"] = true
			case strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://"):
				if _, exists := request["url"]; !exists {
					request["url"] = argument
				}
			}
		}
	case "wget", "fetch":
		for index := 0; index < len(args); index++ {
			argument := args[index]
			switch {
			case (argument == "--header" || argument == "--post-data" || argument == "--post-file") && index+1 < len(args):
				index++
				if argument == "--header" {
					headers = append(headers, args[index])
				} else {
					body = append(body, args[index])
				}
			case strings.HasPrefix(argument, "--header="):
				headers = append(headers, strings.TrimPrefix(argument, "--header="))
			case strings.HasPrefix(argument, "--post-data=") || strings.HasPrefix(argument, "--post-file="):
				_, value, _ := strings.Cut(argument, "=")
				body = append(body, value)
			case argument == "--no-check-certificate":
				request["insecure"] = true
			case strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://"):
				if _, exists := request["url"]; !exists {
					request["url"] = argument
				}
			}
		}
	case "invoke-webrequest", "invoke-restmethod", "iwr", "irm":
		if endpoint, ok := valueAfterFlagFold(args, "-uri"); ok {
			request["url"] = endpoint
		} else {
			for _, argument := range args {
				if strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://") {
					request["url"] = argument
					break
				}
			}
		}
		if method, ok := valueAfterFlagFold(args, "-method"); ok {
			request["method"] = method
		}
		if payload, ok := valueAfterFlagFold(args, "-body"); ok {
			body = append(body, payload)
		}
		if hasArgumentFold(args, "-skipcertificatecheck") {
			request["insecure"] = true
		}
	default:
		return nil, false
	}
	if len(headers) > 0 {
		request["headers"] = headers
	}
	if len(body) > 0 {
		request["body"] = body
	}
	_, hasURL := request["url"]
	return request, hasURL
}

func shellUploadPaths(executable string, args []string) []string {
	var paths []string
	switch executable {
	case "curl":
		for index := 0; index < len(args); index++ {
			argument := args[index]
			switch {
			case (argument == "-T" || argument == "--upload-file") && index+1 < len(args):
				index++
				paths = append(paths, args[index])
			case strings.HasPrefix(argument, "--upload-file="):
				paths = append(paths, strings.TrimPrefix(argument, "--upload-file="))
			case (argument == "-d" || argument == "--data" || argument == "--data-binary" || argument == "-F" || argument == "--form") && index+1 < len(args):
				index++
				if path := uploadReference(args[index]); path != "" {
					paths = append(paths, path)
				}
			case hasAnyPrefix(argument, "--data=", "--data-binary=", "--form="):
				_, value, _ := strings.Cut(argument, "=")
				if path := uploadReference(value); path != "" {
					paths = append(paths, path)
				}
			}
		}
	case "invoke-webrequest", "invoke-restmethod", "iwr", "irm":
		if path, ok := valueAfterFlagFold(args, "-infile"); ok {
			paths = append(paths, path)
		}
	}
	return paths
}

func uploadReference(value string) string {
	if strings.HasPrefix(value, "@") {
		return strings.TrimPrefix(value, "@")
	}
	if _, path, found := strings.Cut(value, "=@"); found {
		return path
	}
	return ""
}

func hasAnyPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func unsafeMode(args []string) bool {
	for _, argument := range args {
		mode := strings.TrimSpace(argument)
		if mode == "777" || mode == "0777" || mode == "666" || mode == "0666" || strings.Contains(strings.ToLower(mode), "a+rwx") || strings.Contains(strings.ToLower(mode), "o+w") {
			return true
		}
	}
	return false
}

func unsafeWindowsACL(args []string) bool {
	joined := strings.ToLower(strings.Join(args, " "))
	return (strings.Contains(joined, "everyone") || strings.Contains(joined, "*s-1-1-0")) &&
		(strings.Contains(joined, ":f") || strings.Contains(joined, "(f)") || strings.Contains(joined, "full"))
}

func hasPowerShellEncodedCommand(args []string) bool {
	for _, argument := range args {
		switch strings.ToLower(argument) {
		case "-encodedcommand", "-enc":
			return true
		}
	}
	return false
}

func containsEnvironmentTarget(args []string) bool {
	for _, argument := range args {
		normalized := strings.ToLower(strings.ReplaceAll(argument, "\\", "/"))
		if strings.Contains(normalized, "env:") {
			return true
		}
	}
	return false
}

func hasAnyFlag(args []string, flags ...string) bool {
	for _, argument := range args {
		if argument == "--" {
			return false
		}
		for _, flag := range flags {
			if argument == flag {
				return true
			}
		}
	}
	return false
}

func hasAnyFlagFold(args []string, flags ...string) bool {
	for _, argument := range args {
		if argument == "--" {
			return false
		}
		for _, flag := range flags {
			if strings.EqualFold(argument, flag) {
				return true
			}
		}
	}
	return false
}

func hasCombinedShortFlag(args []string, wanted byte) bool {
	for _, argument := range args {
		argument = strings.ToLower(argument)
		if argument == "--" {
			return false
		}
		if len(argument) > 2 && argument[0] == '-' && argument[1] != '-' && strings.ContainsRune(argument[1:], rune(wanted)) {
			return true
		}
	}
	return false
}

func hasEnabledPowerShellSwitch(args []string, wanted string) bool {
	for _, argument := range args {
		normalized := strings.ToLower(argument)
		if normalized == strings.ToLower(wanted) {
			return true
		}
		if strings.HasPrefix(normalized, strings.ToLower(wanted)+":") {
			value := strings.TrimPrefix(normalized, strings.ToLower(wanted)+":")
			return value != "$false" && value != "false" && value != "0"
		}
	}
	return false
}

func hasArgumentFold(args []string, target string) bool {
	for _, argument := range args {
		if strings.EqualFold(argument, target) {
			return true
		}
	}
	return false
}

func startsWithFold(args []string, values ...string) bool {
	if len(args) < len(values) {
		return false
	}
	for index, value := range values {
		if !strings.EqualFold(args[index], value) {
			return false
		}
	}
	return true
}

func valueAfterFlag(args []string, flags ...string) (string, bool) {
	for index, argument := range args {
		for _, flag := range flags {
			if argument == flag && index+1 < len(args) {
				return args[index+1], true
			}
		}
	}
	return "", false
}

func valueAfterFlagFold(args []string, flags ...string) (string, bool) {
	for index, argument := range args {
		for _, flag := range flags {
			if strings.EqualFold(argument, flag) && index+1 < len(args) {
				return args[index+1], true
			}
		}
	}
	return "", false
}

func containsExactArgument(args []string, target string) bool {
	for _, argument := range args {
		if filepath.Clean(argument) == filepath.Clean(target) {
			return true
		}
	}
	return false
}

func sameExecutablePath(executable, path string) bool {
	return executable == executableName(path)
}

func stringValues(values []any) ([]string, bool) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}
