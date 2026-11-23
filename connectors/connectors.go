// Package connectors imports every built-in connector so its init registers it.
// Add a line here when a new built-in connector lands in connectors/<name>.
package connectors

import (
	_ "github.com/segurata/segurata/connectors/anthropic"
	_ "github.com/segurata/segurata/connectors/aws"
	_ "github.com/segurata/segurata/connectors/azure"
	_ "github.com/segurata/segurata/connectors/browserext"
	_ "github.com/segurata/segurata/connectors/gcp"
	_ "github.com/segurata/segurata/connectors/googlepersonal"
	_ "github.com/segurata/segurata/connectors/localsecrets"
	_ "github.com/segurata/segurata/connectors/macos"
	_ "github.com/segurata/segurata/connectors/openai"
	_ "github.com/segurata/segurata/connectors/openrouter"
	_ "github.com/segurata/segurata/connectors/supabase"
	_ "github.com/segurata/segurata/connectors/vercel"
)
