"""One module per rule. Every rule exposes check(workflow, triggers) ->
list[Finding]; scanner.py runs all of them and concatenates the results."""
