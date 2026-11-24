*.golden.html are the exact markup of the pages rendered from fixtures/data.
The build-specific values are stored as the placeholders {{VERSION}} and ?v={{HASH}}.
Regenerate them with: go test ./internal/views -update
