package risk

import (
	"regexp"
	"strings"
)

// powerShellMarker recognizes deterministic PowerShell syntax so command text
// receives PowerShell-correct analysis in addition to the POSIX pass. It covers
// Verb-Noun cmdlets, common aliases, and Windows-native commands whose
// backslash paths POSIX lexing would corrupt.
var powerShellMarker = regexp.MustCompile(
	`(?i)(\$env:|-encodedcommand|-executionpolicy|-windowstyle|scriptblock|new-object\b|` +
		`\b(iex|irm|iwr|icm|reg|schtasks|bcdedit|vssadmin|wmic|certutil)\b|` +
		`\b(invoke|get|set|new|remove|start|stop|add|out|write|select|copy|move|test|import|export|register)-[a-z][a-z0-9]*\b)`,
)

func looksLikePowerShell(command string) bool {
	return powerShellMarker.MatchString(command)
}

func powerShellInterpreter(executable string) bool {
	switch executable {
	case "powershell", "pwsh", "iex", "invoke-expression", "invoke-command":
		return true
	default:
		return false
	}
}

// analyzePowerShellText parses command text with PowerShell semantics: backtick
// escapes, subexpressions, script blocks, and grouping parentheses. Detected
// commands then flow through the shared shell behavior analysis.
func analyzePowerShellText(command string, collector *signalCollector, depth int) {
	if strings.TrimSpace(command) == "" {
		return
	}
	if depth >= maxShellNesting {
		collector.add("shell-nesting-limit", 55, "Shell nesting exceeded the safe analysis depth")
		return
	}
	program := parsePowerShell(command)
	if program.malformed {
		collector.add("shell-parse-ambiguity", 45, "PowerShell syntax is incomplete or ambiguous")
	}
	analyzeShellCommands(program.commands, collector, depth, true)
	collectPowerShellTextSignals(command, program.commands, collector)
	for _, substitution := range program.substitutions {
		analyzePowerShellText(substitution, collector, depth+1)
	}
}

// collectPowerShellCommandSignals covers behavior that only exists in
// PowerShell command grammar, such as parenthesized download expressions
// feeding Invoke-Expression.
func collectPowerShellCommandSignals(commands []shellCommand, collector *signalCollector) {
	for _, command := range commands {
		executable, args, _ := resolveShellExecutable(command.words)
		if executable == "" {
			continue
		}
		if isCommandConsumer(executable) || executable == "invoke-command" {
			for _, argument := range args {
				inner, ok := parenthesizedExpression(argument)
				if !ok {
					continue
				}
				if powerShellExpressionDownloads(inner) {
					collector.add("remote-script-execution", 85, "Remote content reaches a command interpreter through a subexpression")
				}
			}
		}
	}
}

// collectPowerShellTextSignals reports .NET download surfaces that appear as
// method calls rather than executables.
func collectPowerShellTextSignals(command string, commands []shellCommand, collector *signalCollector) {
	lowered := strings.ToLower(command)
	downloads := strings.Contains(lowered, "downloadstring") || strings.Contains(lowered, "downloadfile") ||
		strings.Contains(lowered, "downloaddata")
	if !downloads {
		return
	}
	collector.add("remote-content-download", 40, "Command downloads remote content through a .NET client")
	for _, item := range commands {
		executable, _, _ := resolveShellExecutable(item.words)
		if executable == "iex" || executable == "invoke-expression" || executable == "invoke-command" {
			collector.add("remote-script-execution", 85, "Downloaded remote content reaches a command interpreter")
			return
		}
	}
}

func parenthesizedExpression(argument string) (string, bool) {
	trimmed := strings.TrimSpace(argument)
	switch {
	case strings.HasPrefix(trimmed, "$(") && strings.HasSuffix(trimmed, ")"):
		return trimmed[2 : len(trimmed)-1], true
	case strings.HasPrefix(trimmed, "(") && strings.HasSuffix(trimmed, ")"):
		return trimmed[1 : len(trimmed)-1], true
	default:
		return "", false
	}
}

func powerShellExpressionDownloads(expression string) bool {
	lowered := strings.ToLower(expression)
	if strings.Contains(lowered, "downloadstring") || strings.Contains(lowered, "downloadfile") || strings.Contains(lowered, "downloaddata") {
		return true
	}
	program := parsePowerShell(expression)
	for _, command := range program.commands {
		executable, _, _ := resolveShellExecutable(command.words)
		if isDownloader(executable) {
			return true
		}
	}
	return false
}

// parsePowerShell tokenizes one PowerShell command line. Backticks escape the
// next character, single quotes are literal with '' escapes, double quotes
// support backtick escapes, "" escapes, and $() subexpressions. Parentheses and
// script blocks are preserved as words and recorded for nested analysis.
func parsePowerShell(input string) shellProgram {
	tokens, substitutions, malformed := lexPowerShell(input)
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

func lexPowerShell(input string) ([]shellToken, []string, bool) {
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
				if index+1 < len(input) && input[index+1] == '\'' {
					current.WriteByte('\'')
					index++
					continue
				}
				quote = 0
			} else {
				current.WriteByte(character)
			}
			wordStarted = true
			continue
		}
		if quote == '"' {
			switch {
			case character == '"':
				if index+1 < len(input) && input[index+1] == '"' {
					current.WriteByte('"')
					index++
					continue
				}
				quote = 0
				wordStarted = true
			case character == '`':
				if index+1 >= len(input) {
					malformed = true
					continue
				}
				index++
				current.WriteByte(input[index])
				wordStarted = true
			case character == '$' && index+1 < len(input) && input[index+1] == '(':
				content, end, ok := consumePowerShellGroup(input, index+1)
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
			default:
				current.WriteByte(character)
				wordStarted = true
			}
			continue
		}

		switch {
		case character == '\'' || character == '"':
			quote = character
			wordStarted = true
		case character == '`':
			wordStarted = true
			if index+1 >= len(input) {
				malformed = true
				continue
			}
			index++
			current.WriteByte(input[index])
		case character == '$' && index+1 < len(input) && input[index+1] == '(':
			content, end, ok := consumePowerShellGroup(input, index+1)
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
		case character == '(':
			content, end, ok := consumePowerShellGroup(input, index)
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
		case character == '{':
			content, end, ok := consumePowerShellBlock(input, index)
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
		case character == '<' && index+1 < len(input) && input[index+1] == '#':
			end := strings.Index(input[index+2:], "#>")
			if end < 0 {
				malformed = true
				index = len(input)
				continue
			}
			index += 2 + end + 1
		case character == '#':
			if wordStarted {
				current.WriteByte(character)
				continue
			}
			for index < len(input) && input[index] != '\n' {
				index++
			}
			flush()
			if index < len(input) {
				tokens = append(tokens, shellToken{word: ";", separator: true})
			}
		case character == ' ' || character == '\t' || character == '\r':
			flush()
		case character == '\n':
			flush()
			tokens = append(tokens, shellToken{word: ";", separator: true})
		case character == ';':
			flush()
			tokens = append(tokens, shellToken{word: ";", separator: true})
		case character == '|':
			flush()
			operator := "|"
			if index+1 < len(input) && input[index+1] == '|' {
				operator = "||"
				index++
			}
			tokens = append(tokens, shellToken{word: operator, separator: true})
		case character == '&':
			flush()
			if index+1 < len(input) && input[index+1] == '&' {
				tokens = append(tokens, shellToken{word: "&&", separator: true})
				index++
				continue
			}
			// A lone ampersand is the call operator or a background job
			// marker; either way the following words form a command.
			tokens = append(tokens, shellToken{word: ";", separator: true})
		case character == '<' || character == '>':
			flush()
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

// consumePowerShellGroup returns the content of one balanced parenthesized
// group starting at input[start] == '('.
func consumePowerShellGroup(input string, start int) (string, int, bool) {
	return consumeBalanced(input, start, '(', ')')
}

func consumePowerShellBlock(input string, start int) (string, int, bool) {
	return consumeBalanced(input, start, '{', '}')
}

func consumeBalanced(input string, start int, open, close byte) (string, int, bool) {
	depth := 0
	quote := byte(0)
	for index := start; index < len(input); index++ {
		character := input[index]
		if quote != 0 {
			if character == '`' && quote == '"' {
				index++
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '`':
			index++
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return input[start+1 : index], index, true
			}
		}
	}
	return "", len(input), false
}

// hasExecutionPolicyBypassFlag detects powershell.exe / pwsh invocation flags
// that disable script execution policy, including accepted abbreviations.
func hasExecutionPolicyBypassFlag(args []string) bool {
	for index, argument := range args {
		normalized := strings.ToLower(argument)
		if !strings.HasPrefix(normalized, "-e") {
			continue
		}
		rest := strings.TrimPrefix(normalized, "-")
		if rest != "ep" && !(len(rest) >= 2 && strings.HasPrefix("executionpolicy", rest)) {
			continue
		}
		if index+1 < len(args) {
			value := strings.ToLower(args[index+1])
			if value == "bypass" || value == "unrestricted" {
				return true
			}
		}
	}
	return false
}

// hasWindowStyleHidden detects hidden-window execution requested on a
// powershell.exe / pwsh command line.
func hasWindowStyleHidden(args []string) bool {
	for index, argument := range args {
		normalized := strings.ToLower(argument)
		if !strings.HasPrefix(normalized, "-w") {
			continue
		}
		rest := strings.TrimPrefix(normalized, "-")
		if !strings.HasPrefix("windowstyle", rest) {
			continue
		}
		if index+1 < len(args) {
			value := strings.ToLower(args[index+1])
			if value == "hidden" || value == "1" {
				return true
			}
		}
	}
	return false
}

func containsWindowsRunKey(args []string) bool {
	for _, argument := range args {
		normalized := strings.ToLower(strings.ReplaceAll(argument, "/", "\\"))
		if strings.Contains(normalized, "currentversion\\run") {
			return true
		}
	}
	return false
}
