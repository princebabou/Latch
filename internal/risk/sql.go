package risk

import (
	"strings"

	"github.com/princebabou/Latch/pkg/models"
)

type sqlTokenKind uint8

const (
	sqlWord sqlTokenKind = iota
	sqlLiteral
	sqlSymbol
)

type sqlToken struct {
	kind  sqlTokenKind
	value string
}

func collectSQLSignals(action models.Action, collector *signalCollector) {
	raw, ok := firstValue(action.Arguments, "query", "sql", "statement")
	if !ok {
		return
	}
	switch query := raw.(type) {
	case string:
		analyzeSQL(query, collector)
	case []string:
		for _, statement := range query {
			analyzeSQL(statement, collector)
		}
	case []any:
		for _, statement := range query {
			text, ok := statement.(string)
			if !ok {
				collector.add("sql-parse-ambiguity", 45, "SQL batch contains a non-text statement")
				continue
			}
			analyzeSQL(text, collector)
		}
	default:
		collector.add("sql-parse-ambiguity", 45, "SQL input could not be interpreted safely")
	}
}

// DatabaseOperations returns executable top-level and nested SQL operations
// while ignoring comments and string literals. Policy matching uses this same
// parser, so risk detection and database_operation rules cannot disagree.
func DatabaseOperations(query string) []string {
	tokens, _ := lexSQL(query)
	statements, _ := splitSQLStatements(tokens)
	seen := make(map[string]bool)
	var operations []string
	var collect func([]sqlToken, int)
	collect = func(statement []sqlToken, depth int) {
		if depth > 12 {
			return
		}
		if operation := strings.ToUpper(sqlOperation(statement)); operation != "" && !seen[operation] {
			seen[operation] = true
			operations = append(operations, operation)
		}
		for _, nested := range nestedSQLStatements(statement) {
			collect(nested, depth+1)
		}
	}
	for _, statement := range statements {
		collect(statement, 0)
	}
	return operations
}

func analyzeSQL(query string, collector *signalCollector) {
	if strings.TrimSpace(query) == "" {
		return
	}
	tokens, malformed := lexSQL(query)
	statements, unbalanced := splitSQLStatements(tokens)
	if malformed || unbalanced {
		collector.add("sql-parse-ambiguity", 45, "SQL syntax is incomplete or structurally ambiguous")
	}
	if len(statements) > 1 {
		collector.add("multi-statement-query", 30, "Multiple SQL statements were submitted in one action")
	}

	for _, statement := range statements {
		analyzeSQLStatement(statement, collector, 0)
	}
}

func analyzeSQLStatement(statement []sqlToken, collector *signalCollector, depth int) {
	if depth > 12 {
		collector.add("sql-nesting-limit", 55, "SQL nesting exceeded the safe analysis depth")
		return
	}
	operation := sqlOperation(statement)
	switch operation {
	case "drop", "truncate", "delete":
		collector.add("destructive-database-query", 80, "Destructive database statement detected")
	case "alter":
		collector.add("database-schema-change", 65, "Database schema alteration detected")
		if containsTopLevelSequence(statement, "alter", "user") || containsTopLevelSequence(statement, "alter", "role") {
			collector.add("database-privilege-change", 80, "Database principal alteration detected")
		}
	case "grant", "revoke":
		collector.add("database-privilege-change", 80, "Database privilege change detected")
	case "create":
		if containsTopLevelSequence(statement, "user") || containsTopLevelSequence(statement, "role") {
			collector.add("database-privilege-change", 80, "Database principal creation detected")
		}
	case "merge":
		collector.add("database-mutation", 55, "MERGE statement can modify multiple database rows")
	}

	if (operation == "delete" || operation == "update") && !hasTopLevelWord(statement, "where") {
		collector.add("unscoped-database-mutation", 90, "Database mutation has no top-level WHERE clause")
	}
	if operation == "select" && projectionHasWildcard(statement) && !hasQueryBound(statement) {
		collector.add("unbounded-database-query", 45, "Wildcard SELECT has no top-level result bound")
	}
	if operation == "select" && containsTopLevelSequence(statement, "for", "update") {
		collector.add("locking-database-query", 25, "SELECT FOR UPDATE can lock database rows")
	}
	if databaseCommandExecution(statement) {
		collector.add("database-command-execution", 95, "Database statement can execute an operating-system command")
	}
	if databaseFileAccess(statement) {
		collector.add("database-file-access", 75, "Database statement accesses the server filesystem")
	}
	if referencesSensitiveIdentifier(statement) {
		collector.add("sensitive-database-column", 40, "Query references a sensitive data identifier")
	}

	for _, nested := range nestedSQLStatements(statement) {
		nestedOperation := sqlOperation(nested)
		switch nestedOperation {
		case "select", "insert", "update", "delete", "merge", "with":
			analyzeSQLStatement(nested, collector, depth+1)
		}
	}
}

func nestedSQLStatements(statement []sqlToken) [][]sqlToken {
	var nested [][]sqlToken
	start := -1
	depth := 0
	for index, token := range statement {
		if token.kind != sqlSymbol {
			continue
		}
		switch token.value {
		case "(":
			if depth == 0 {
				start = index + 1
			}
			depth++
		case ")":
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 && start >= 0 && start < index {
				nested = append(nested, statement[start:index])
				start = -1
			}
		}
	}
	return nested
}

func lexSQL(query string) ([]sqlToken, bool) {
	tokens := make([]sqlToken, 0, len(query)/4)
	malformed := false
	for index := 0; index < len(query); {
		character := query[index]
		switch {
		case isSQLSpace(character):
			index++
		case character == '-' && index+1 < len(query) && query[index+1] == '-':
			index += 2
			for index < len(query) && query[index] != '\n' {
				index++
			}
		case character == '#':
			index++
			for index < len(query) && query[index] != '\n' {
				index++
			}
		case character == '/' && index+1 < len(query) && query[index+1] == '*':
			content, end, ok, executable := consumeSQLBlockComment(query, index)
			if !ok {
				malformed = true
				index = len(query)
			} else {
				if executable {
					content = strings.TrimSpace(strings.TrimPrefix(content, "!"))
					content = strings.TrimLeft(content, "0123456789 ")
					innerTokens, innerMalformed := lexSQL(content)
					tokens = append(tokens, innerTokens...)
					malformed = malformed || innerMalformed
				}
				index = end
			}
		case character == '\'':
			value, end, ok := consumeSQLQuoted(query, index, '\'', '\'')
			tokens = append(tokens, sqlToken{kind: sqlLiteral, value: value})
			if !ok {
				malformed = true
				index = len(query)
			} else {
				index = end
			}
		case character == '"' || character == '`':
			value, end, ok := consumeSQLQuoted(query, index, character, character)
			tokens = append(tokens, sqlToken{kind: sqlWord, value: strings.ToLower(value)})
			if !ok {
				malformed = true
				index = len(query)
			} else {
				index = end
			}
		case character == '[':
			value, end, ok := consumeSQLQuoted(query, index, '[', ']')
			tokens = append(tokens, sqlToken{kind: sqlWord, value: strings.ToLower(value)})
			if !ok {
				malformed = true
				index = len(query)
			} else {
				index = end
			}
		case character == '$':
			if delimiter, ok := sqlDollarDelimiter(query[index:]); ok {
				endOffset := strings.Index(query[index+len(delimiter):], delimiter)
				if endOffset < 0 {
					tokens = append(tokens, sqlToken{kind: sqlLiteral})
					malformed = true
					index = len(query)
				} else {
					start := index + len(delimiter)
					tokens = append(tokens, sqlToken{kind: sqlLiteral, value: query[start : start+endOffset]})
					index = start + endOffset + len(delimiter)
				}
			} else {
				tokens = append(tokens, sqlToken{kind: sqlSymbol, value: "$"})
				index++
			}
		case isSQLWordStart(character):
			start := index
			index++
			for index < len(query) && isSQLWordPart(query[index]) {
				index++
			}
			tokens = append(tokens, sqlToken{kind: sqlWord, value: strings.ToLower(query[start:index])})
		case character >= '0' && character <= '9':
			start := index
			index++
			for index < len(query) && ((query[index] >= '0' && query[index] <= '9') || query[index] == '.') {
				index++
			}
			tokens = append(tokens, sqlToken{kind: sqlLiteral, value: query[start:index]})
		default:
			tokens = append(tokens, sqlToken{kind: sqlSymbol, value: string(character)})
			index++
		}
	}
	return tokens, malformed
}

func consumeSQLBlockComment(query string, start int) (string, int, bool, bool) {
	depth := 1
	executable := start+2 < len(query) && query[start+2] == '!'
	for index := start + 2; index < len(query)-1; index++ {
		if query[index] == '/' && query[index+1] == '*' {
			depth++
			index++
			continue
		}
		if query[index] == '*' && query[index+1] == '/' {
			depth--
			index++
			if depth == 0 {
				return query[start+2 : index-1], index + 1, true, executable
			}
		}
	}
	return "", len(query), false, executable
}

func consumeSQLQuoted(query string, start int, opening, closing byte) (string, int, bool) {
	var value strings.Builder
	for index := start + 1; index < len(query); index++ {
		if query[index] == closing {
			if index+1 < len(query) && query[index+1] == closing {
				value.WriteByte(closing)
				index++
				continue
			}
			return value.String(), index + 1, true
		}
		if query[index] == '\\' && opening != '[' && index+1 < len(query) {
			index++
			value.WriteByte(query[index])
			continue
		}
		value.WriteByte(query[index])
	}
	return value.String(), len(query), false
}

func sqlDollarDelimiter(input string) (string, bool) {
	if len(input) < 2 || input[0] != '$' {
		return "", false
	}
	for index := 1; index < len(input); index++ {
		if input[index] == '$' {
			return input[:index+1], true
		}
		if !((input[index] >= 'a' && input[index] <= 'z') || (input[index] >= 'A' && input[index] <= 'Z') || (input[index] >= '0' && input[index] <= '9') || input[index] == '_') {
			return "", false
		}
	}
	return "", false
}

func splitSQLStatements(tokens []sqlToken) ([][]sqlToken, bool) {
	var statements [][]sqlToken
	var current []sqlToken
	depth := 0
	unbalanced := false
	flush := func() {
		if len(current) > 0 {
			statements = append(statements, current)
			current = nil
		}
	}
	for _, token := range tokens {
		if token.kind == sqlSymbol {
			switch token.value {
			case "(":
				depth++
			case ")":
				depth--
				if depth < 0 {
					unbalanced = true
					depth = 0
				}
			case ";":
				if depth == 0 {
					flush()
					continue
				}
			}
		}
		current = append(current, token)
	}
	flush()
	return statements, unbalanced || depth != 0
}

func sqlOperation(statement []sqlToken) string {
	index := nextSQLWord(statement, 0)
	if index < 0 {
		return ""
	}
	if statement[index].value == "explain" {
		index = nextSQLWord(statement, index+1)
		if index >= 0 && (statement[index].value == "analyze" || statement[index].value == "analyse") {
			index = nextSQLWord(statement, index+1)
		}
		if index < 0 {
			return ""
		}
	}
	if statement[index].value != "with" {
		return statement[index].value
	}

	depth := 0
	for index++; index < len(statement); index++ {
		token := statement[index]
		if token.kind == sqlSymbol {
			if token.value == "(" {
				depth++
			}
			if token.value == ")" && depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && token.kind == sqlWord {
			switch token.value {
			case "select", "insert", "update", "delete", "merge":
				return token.value
			}
		}
	}
	return "with"
}

func nextSQLWord(tokens []sqlToken, start int) int {
	for index := start; index < len(tokens); index++ {
		if tokens[index].kind == sqlWord {
			return index
		}
	}
	return -1
}

func hasTopLevelWord(statement []sqlToken, wanted string) bool {
	depth := 0
	for _, token := range statement {
		if token.kind == sqlSymbol {
			if token.value == "(" {
				depth++
			}
			if token.value == ")" && depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && token.kind == sqlWord && token.value == wanted {
			return true
		}
	}
	return false
}

func containsTopLevelSequence(statement []sqlToken, wanted ...string) bool {
	depth := 0
	var words []string
	for _, token := range statement {
		if token.kind == sqlSymbol {
			if token.value == "(" {
				depth++
			}
			if token.value == ")" && depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && token.kind == sqlWord {
			words = append(words, token.value)
		}
	}
	for index := 0; index+len(wanted) <= len(words); index++ {
		matches := true
		for offset, value := range wanted {
			if words[index+offset] != value {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func projectionHasWildcard(statement []sqlToken) bool {
	depth := 0
	inProjection := false
	rootSelect := sqlOperation(statement) == "select"
	for _, token := range statement {
		if token.kind == sqlSymbol {
			if token.value == "(" {
				depth++
			}
			if token.value == ")" && depth > 0 {
				depth--
			}
			if depth == 0 && inProjection && token.value == "*" {
				return true
			}
			continue
		}
		if depth == 0 && token.kind == sqlWord {
			if token.value == "select" && rootSelect {
				inProjection = true
				continue
			}
			if inProjection && token.value == "from" {
				return false
			}
		}
	}
	return false
}

func hasQueryBound(statement []sqlToken) bool {
	return hasTopLevelWord(statement, "limit") ||
		hasTopLevelWord(statement, "fetch") ||
		hasTopLevelWord(statement, "top")
}

func databaseCommandExecution(statement []sqlToken) bool {
	if (hasSQLWord(statement, "copy") && hasSQLWord(statement, "program")) ||
		containsWordSequence(statement, "xp_cmdshell") ||
		containsWordSequence(statement, "sys_exec") ||
		containsWordSequence(statement, "sys_eval") {
		return true
	}
	return false
}

func hasSQLWord(statement []sqlToken, wanted string) bool {
	for _, token := range statement {
		if token.kind == sqlWord && token.value == wanted {
			return true
		}
	}
	return false
}

func databaseFileAccess(statement []sqlToken) bool {
	return containsWordSequence(statement, "into", "outfile") ||
		containsWordSequence(statement, "into", "dumpfile") ||
		containsWordSequence(statement, "load_file") ||
		containsWordSequence(statement, "pg_read_file") ||
		containsWordSequence(statement, "pg_write_file") ||
		containsWordSequence(statement, "lo_import") ||
		containsWordSequence(statement, "lo_export") ||
		containsWordSequence(statement, "attach", "database")
}

func containsWordSequence(statement []sqlToken, wanted ...string) bool {
	var words []string
	for _, token := range statement {
		if token.kind == sqlWord {
			words = append(words, token.value)
		}
	}
	for index := 0; index+len(wanted) <= len(words); index++ {
		match := true
		for offset, value := range wanted {
			if words[index+offset] != value {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func referencesSensitiveIdentifier(statement []sqlToken) bool {
	for _, token := range statement {
		if token.kind == sqlWord && sensitiveName(token.value) {
			return true
		}
	}
	return false
}

func isSQLSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n' || character == '\f'
}

func isSQLWordStart(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_'
}

func isSQLWordPart(character byte) bool {
	return isSQLWordStart(character) || (character >= '0' && character <= '9') || character == '$'
}
