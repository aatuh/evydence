package wiring

import packagequery "github.com/aatuh/evydence/internal/package/query"

// BuildAnswerLibraryQuery binds package-owned read policy to the durable,
// grant-filtered questionnaire draft page.
func BuildAnswerLibraryQuery(reader packagequery.AnswerLibraryReader) (*packagequery.AnswerLibrary, error) {
	return packagequery.NewAnswerLibrary(reader)
}
